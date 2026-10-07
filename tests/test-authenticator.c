/* Exercise the real handlers without accessing the user's keyring or bus. */
#include <libsecret/secret.h>
static char *stored_token;
static gboolean
test_password_store (const SecretSchema *schema, const char *collection,
                     const char *label, const char *password,
                     GCancellable *cancellable, GError **error, ...)
{
  (void) schema;
  (void) collection;
  (void) label;
  (void) cancellable;
  (void) error;
  g_free (stored_token);
  stored_token = g_strdup (password);
  return TRUE;
}
#define secret_password_store_sync test_password_store
#define main authenticator_main
#include "../src/main.c"
#undef main

static unsigned int response_count;
static unsigned int response_code;
static char *webflow_url;
static unsigned int backend_status = SOUP_STATUS_OK;

static void
response_cb (FlatpakAuthenticatorRequest *impl,
             unsigned int code,
             GVariant *results,
             gpointer data)
{
  (void) impl;
  (void) results;
  (void) data;
  response_count ++;
  response_code = code;
}

static void
webflow_cb (FlatpakAuthenticatorRequest *impl,
            const char *url,
            GVariant *options,
            gpointer data)
{
  (void) impl;
  (void) options;
  (void) data;
  g_free (webflow_url);
  webflow_url = g_strdup (url);
}

static ActiveRequest *
new_request (void)
{
  ActiveRequest *req = g_new0 (ActiveRequest, 1);
  const char *refs[] = { "app/org.example.App/x86_64/stable&return=evil#fragment", NULL };

  req->ref_count = 1;
  req->cancellable = g_cancellable_new ();
  req->request_impl = flatpak_authenticator_request_skeleton_new ();
  req->refs = g_strdupv ((char **) refs);
  active_requests ++;
  response_count = 0;
  g_clear_pointer (&stored_token, g_free);
  g_clear_pointer (&webflow_url, g_free);
  g_signal_connect (req->request_impl, "response", G_CALLBACK (response_cb), NULL);
  g_signal_connect (req->request_impl, "webflow", G_CALLBACK (webflow_cb), NULL);
  return req;
}

static void
test_webflow_url (void)
{
  ActiveRequest *req = new_request ();
  g_autoptr(SoupURI) uri = NULL;
  g_autoptr(GHashTable) query = NULL;
  g_autoslist(SoupURI) uris = NULL;
  g_autofree char *return_uri = NULL;

  redirect_to_frontend (req);
  uri = soup_uri_new (webflow_url);
  query = soup_form_decode (uri->query);
  uris = soup_server_get_uris (req->return_server);
  return_uri = soup_uri_to_string (uris->data, FALSE);
  g_assert_cmpuint (g_hash_table_size (query), ==, 2);
  g_assert_cmpstr (g_hash_table_lookup (query, "refs"), ==, req->refs[0]);
  g_assert_cmpstr (g_hash_table_lookup (query, "return"), ==, return_uri);
  g_assert_null (uri->fragment);
  end_request_with_cancellation (req);
  g_assert_cmpint (active_requests, ==, 0);
}

static void
server_cb (SoupServer *server, SoupMessage *msg, const char *path,
           GHashTable *query, SoupClientContext *client, gpointer data)
{
  (void) server;
  (void) path;
  (void) query;
  (void) client;
  soup_message_set_status (msg, backend_status);
  soup_message_set_response (msg, "application/json", SOUP_MEMORY_COPY,
                             data, strlen (data));
}

static gboolean
test_timeout (gpointer data)
{
  (void) data;
  g_error ("Timed out waiting for request completion");
  return G_SOURCE_REMOVE;
}

static void
run_backend (const char *body, gboolean cancel)
{
  g_autoptr(SoupServer) server = soup_server_new (NULL, NULL);
  g_autoptr(SoupSession) session = soup_session_new ();
  g_autoslist(SoupURI) uris = NULL;
  g_autofree char *uri = NULL;
  g_autoptr(GError) error = NULL;
  ActiveRequest *req = new_request ();
  DownloadTokenRequest *data = g_new0 (DownloadTokenRequest, 1);
  unsigned int timeout;
  g_autoptr(GProxyResolver) proxy = g_simple_proxy_resolver_new (NULL, NULL);

  g_object_set (session, "proxy-resolver", proxy, NULL);
  req->didWebflow = TRUE;
  soup_server_add_handler (server, NULL, server_cb, (void *) body, NULL);
  g_assert_true (soup_server_listen_local (server, 0, 0, &error));
  g_assert_no_error (error);
  uris = soup_server_get_uris (server);
  uri = soup_uri_to_string (uris->data, FALSE);
  data->message = soup_message_new ("POST", uri);
  data->request = req;
  req->ref_count ++;
  soup_session_send_async (session, data->message, req->cancellable,
                           on_download_token_request_sent, data);
  if (cancel)
    end_request_with_cancellation (req);
  timeout = g_timeout_add_seconds (5, test_timeout, NULL);
  while (active_requests != 0)
    g_main_context_iteration (NULL, TRUE);
  g_source_remove (timeout);
  g_assert_cmpuint (response_count, ==, 1);
}

static void
test_cancel_pending (void)
{
  run_backend ("{\"token\":\"download\"}", TRUE);
  g_assert_cmpuint (response_code, ==, 1);
}

static void
test_backend_success (void)
{
  run_backend ("{\"token\":\"download\"}", FALSE);
  g_assert_cmpuint (response_code, ==, 0);
}

static void
test_backend_invalid (void)
{
  const char *bodies[] = { "broken", "null", "[]", "{}",
    "{\"token\":42}", "{\"token\":null}", "{\"update-token\":{}}",
    "{\"token\":\"\"}", "{\"token\":\"bad\\r\\ntoken\"}",
    "{\"token\":\"good\",\"update-token\":false}",
    "{\"missing_appids\":false}", "{\"missing_appids\":[42]}",
    "{\"update-token\":\"must-not-store\"}" };
  for (size_t i = 0; i < G_N_ELEMENTS (bodies); i ++)
    {
      run_backend (bodies[i], FALSE);
      g_assert_cmpuint (response_code, ==, 2);
      g_assert_null (stored_token);
    }
}

static void
test_backend_rotation (void)
{
  run_backend ("{\"token\":\"download\",\"update-token\":\"rotated\"}", FALSE);
  g_assert_cmpuint (response_code, ==, 0);
  g_assert_cmpstr (stored_token, ==, "rotated");
}

static void
test_backend_http_error (void)
{
  const unsigned int statuses[] = { 302, 401, 403, 429, 500 };
  for (size_t i = 0; i < G_N_ELEMENTS (statuses); i ++)
    {
      backend_status = statuses[i];
      run_backend ("{\"token\":\"must-not-accept\",\"update-token\":\"must-not-store\"}", FALSE);
      g_assert_cmpuint (response_code, ==, 2);
      g_assert_null (stored_token);
    }
  backend_status = SOUP_STATUS_OK;
}

static void
test_callbacks (void)
{
  ActiveRequest *req = new_request ();
  const char *queries[] = { "", "unknown=x", "token=", "download-token=",
                           "download-token=bad%0D%0Atoken", "token=&download-token=good" };

  for (size_t i = 0; i < G_N_ELEMENTS (queries); i ++)
    {
      g_autoptr(SoupMessage) msg = soup_message_new ("GET", "http://127.0.0.1/success");
      g_autoptr(GHashTable) query = soup_form_decode (queries[i]);
      handle_return_request (NULL, msg, "/success", query, NULL, req);
      g_assert_cmpuint (msg->status_code, ==, 400);
      g_assert_cmpuint (response_count, ==, 0);
      g_assert_null (stored_token);
    }
  {
    g_autoptr(SoupMessage) msg = soup_message_new ("POST", "http://127.0.0.1/cancel");
    handle_cancel_request (NULL, msg, "/cancel", NULL, NULL, req);
    g_assert_cmpuint (msg->status_code, ==, 405);
    g_object_set (msg, "method", "GET", NULL);
    soup_message_headers_replace (msg->request_headers, "Origin", "https://evil.example");
    handle_cancel_request (NULL, msg, "/cancel", NULL, NULL, req);
    g_assert_cmpuint (msg->status_code, ==, 403);
    g_assert_cmpuint (response_count, ==, 0);
  }
  {
    g_autoptr(SoupMessage) msg = soup_message_new ("GET", "http://127.0.0.1/success");
    g_autoptr(GHashTable) query = soup_form_decode ("download-token=good&unknown=ignored");
    handle_return_request (NULL, msg, "/success/extra", query, NULL, req);
    g_assert_cmpuint (msg->status_code, ==, 404);
    handle_return_request (NULL, msg, "/success", query, NULL, req);
    g_assert_cmpuint (msg->status_code, ==, 200);
    g_assert_cmpuint (response_code, ==, 0);
    g_assert_cmpuint (response_count, ==, 1);
  }
  g_assert_cmpint (active_requests, ==, 0);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/webflow/url", test_webflow_url);
  g_test_add_func ("/backend/cancel-pending", test_cancel_pending);
  g_test_add_func ("/backend/success", test_backend_success);
  g_test_add_func ("/backend/invalid", test_backend_invalid);
  g_test_add_func ("/backend/rotation", test_backend_rotation);
  g_test_add_func ("/backend/http-error", test_backend_http_error);
  g_test_add_func ("/webflow/callbacks", test_callbacks);
  int result = g_test_run ();
  g_free (webflow_url);
  g_free (stored_token);
  return result;
}

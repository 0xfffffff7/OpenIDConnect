using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Configuration;
using System.Net.Http;
using System.Net;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;
using System.IO;

namespace OpenIDConnect
{
    public partial class OpenIDConnect : System.Web.UI.Page
    {
        // JSON 整形
        private static string format_json(string json)
        {
            dynamic parsedJson = JsonConvert.DeserializeObject(json);
            return JsonConvert.SerializeObject(parsedJson, Formatting.Indented);
        }

        protected void Page_Load(object sender, EventArgs e)
        {

            //-----------------------------------------------------------------------
            // エラー検査.
            //-----------------------------------------------------------------------

            // エラーコード.
            string error = Request["error"];

            // エラー詳細.
            string error_description = Request["error_description"];

            // エラー詳細情報を記載したURL.
            string error_uri = Request["error_uri"];

            string resHtml = string.Empty;
            if (string.IsNullOrEmpty(error) == false)
            {
                resHtml += "error=";
                resHtml += error;
                resHtml += "<BR>";

                if (string.IsNullOrEmpty(error_description) == false)
                {
                    resHtml += "error_description=";
                    resHtml += error_description;
                    resHtml += "<BR>";
                }

                if (string.IsNullOrEmpty(error_uri) == false)
                {
                    resHtml += "error_uri=";
                    resHtml += error_uri;
                    resHtml += "<BR>";
                }

                LABEL1.Text = HttpUtility.HtmlEncode(resHtml);
                return;

            }
            else
            {
                //-----------------------------------------------------------------------
                // 認可成功.
                //-----------------------------------------------------------------------

                string clientID = ConfigurationManager.AppSettings["CLIENT_ID"];
                string clientSecret = ConfigurationManager.AppSettings["CLIENT_SECRET"];
                string redirect_uri = ConfigurationManager.AppSettings["CALLBACK_URL"];

                // 認可コードを取得する.
                string code = Request["code"];
                if (string.IsNullOrEmpty(code))
                {
                    resHtml += "code is none.";
                    resHtml += "<BR>";
                    LABEL1.Text = HttpUtility.HtmlEncode(resHtml);
                    return;
                }

                // nonceをチェックする.
                string state = Request["state"];
                if (string.IsNullOrEmpty(state) && Session["state"].ToString() != state)
                {
                    resHtml += "state is Invalid.";
                    resHtml += "<BR>";
                    LABEL1.Text = HttpUtility.HtmlEncode(resHtml);
                    return;
                }

                //-----------------------------------------------------------------------
                // アクセストークンを要求するためのURLを作成.
                // 次の変数をPOSTする.
                //   認可コード.
                //   コールバックURL.認可時に使用したものと同じ.
                //   グラントタイプ
                //   client_id
                //   client_secret
                //-----------------------------------------------------------------------

                string url = Session["token_endpoint"].ToString();

                System.Net.WebClient wc = new System.Net.WebClient();

                // POSTデータの作成.
                System.Collections.Specialized.NameValueCollection ps =
                    new System.Collections.Specialized.NameValueCollection();

                //アプリケーションに渡された認可コード。
                ps.Add("code", code);

                // コールバックURL.
                ps.Add("redirect_uri", redirect_uri);

                // グラントタイプ.
                // 認可コードをアクセストークンに交換する場合は「authorization_code」を指定する。
                ps.Add("grant_type", "authorization_code");

                // BASIC認証でclient_secretを渡すか、
                // POSTでclient_idとclient_secret各種の値を渡す.
                ps.Add("client_id", clientID);
                ps.Add("client_secret", clientSecret);

                //データを送受信する
                byte[] resData = wc.UploadValues(url, ps);
                wc.Dispose();

                //受信したデータを表示する
                string tokenResponse = System.Text.Encoding.UTF8.GetString(resData);

                // レスポンスはサービスによって変わる。
                // Googleの場合はJSON
                // Facebookの場合はフォームエンコードされた&区切りのKey=Valueが返る。

                LABEL1.Text = format_json(tokenResponse);
                LABEL1.Text += "<br><br><br>";


                // access_token、expires_in、id_token の保存。
                var json_tokenResponse = JObject.Parse(tokenResponse);
                Session["access_token"] = json_tokenResponse["access_token"].ToString();
                Session["expires_in"] = json_tokenResponse["expires_in"].ToString();
                Session["id_token"] = json_tokenResponse["id_token"].ToString();


                // IDトークンの検証

                // JWKの公開鍵一覧を取得する。
                Stream st = wc.OpenRead(Session["jwks_uri"].ToString());
                StreamReader sr = new StreamReader(st);
                string jwksResponse = sr.ReadToEnd();
                sr.Close();
                st.Close();

                if (JWTValidator.Validation(Session["id_token"].ToString(), jwksResponse) == false)
                {
                    LABEL1.Text += "Verify Failed!!.";
                    LABEL1.Text += "<br><br><br>";
                    return;
                }


                string userInfoResponse = string.Empty;
                try
                {
                    // Google+の権限が必要。
                    string userinfo_endpoint = Session["userinfo_endpoint"].ToString();
                    wc.Headers.Add("Authorization: OAuth " + Session["access_token"]);
                    using (st = wc.OpenRead(userinfo_endpoint))
                    {
                        Encoding enc = Encoding.GetEncoding("utf-8");
                        using (sr = new StreamReader(st, enc))
                        {
                            userInfoResponse = format_json(sr.ReadToEnd());
                        }
                    }
                }
                catch (Exception ex)
                {
                    LABEL1.Text = ex.Message;
                    return;
                }

                JWTValidator.JWTProperty jwtp = JWTValidator.JWTDecode(Session["id_token"].ToString());
                LABEL1.Text += jwtp._header;
                LABEL1.Text += "<br><br>";
                LABEL1.Text += jwtp._payload;
                LABEL1.Text += "<br><br><br>";

                LABEL1.Text += userInfoResponse;
            }
        }

    }
}
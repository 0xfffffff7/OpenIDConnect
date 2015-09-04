using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Configuration;
using System.IO;
using Newtonsoft.Json.Linq;

namespace OpneIDConnect
{
    public partial class defalut : System.Web.UI.Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            string oauth = Request["openidconnect"];
            if (string.IsNullOrEmpty(oauth) == false)
            {
                string clientID = ConfigurationManager.AppSettings["CLIENT_ID"];
                string OpenIdProviderURL = ConfigurationManager.AppSettings["OPENID_PROVIDER_URL"];


                // OPENIDのエンドポイント情報を得る。
                OpenIdProviderURL += ".well-known/openid-configuration";

                string configuration = string.Empty;
                using (System.Net.WebClient wc = new System.Net.WebClient())
                {
                    Stream st = wc.OpenRead(OpenIdProviderURL);
                    StreamReader sr = new StreamReader(st);
                    configuration = sr.ReadToEnd();
                    sr.Close();
                    st.Close();
                }

                var json_configuration = JObject.Parse(configuration);

                // AUTHエンドポイント
                string authorization_endpoint = json_configuration["authorization_endpoint"].ToString();

                // トークンエンドポイント
                Session["token_endpoint"] = json_configuration["token_endpoint"].ToString();

                // JWKSのURL(JWTの署名検証で使う)
                Session["jwks_uri"] = json_configuration["jwks_uri"].ToString();

                // userinfo_endpoint
                Session["userinfo_endpoint"] = json_configuration["userinfo_endpoint"].ToString();
                


                // ユーザーキー.
                string client_id = clientID;

                // 認可後のコールバックURL.
                string redirect_uri = ConfigurationManager.AppSettings["CALLBACK_URL"];

                // OpenIdConnectの要求スコープ.
                string scope = "openid%20email&profile";

                // リクエストタイプ.ウェブアプリケーションフローなので認可コードを意味する「code」を指定する。
                string response_type = "code";
                
                string realm =  ConfigurationManager.AppSettings["OPENID_REALM"];

                // XSRF対策でnonceを生成.
                Guid guidValue = Guid.NewGuid();
                string state = guidValue.ToString();
                Session["state"] = state;

                // URL作成.
                authorization_endpoint += "?client_id=" + clientID;
                authorization_endpoint += "&redirect_uri=" + HttpUtility.UrlEncode(redirect_uri);
                authorization_endpoint += "&response_type=" + response_type;
                authorization_endpoint += "&state=" + state;
                authorization_endpoint += "&scope=" + scope;
                //authorization_endpoint += "&openid.realm=" + realm;


                Response.Redirect(authorization_endpoint);
            }
        }
    }
}
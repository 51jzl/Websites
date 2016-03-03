namespace Microsoft.Owin.Security.QQ
{
    internal static class Constants
    {
        public const string DefaultAuthenticationType = "QQ";

        internal const string AuthorizationEndpoint = "https://graph.qq.com/oauth2.0/authorize";
        internal const string TokenEndpoint = "https://graph.qq.com/oauth2.0/token";
        internal const string OpenIdEndpoint = "https://graph.qq.com/oauth2.0/me";
        internal const string UserInformationEndpoint = "https://graph.qq.com/user/get_user_info";
    }
}

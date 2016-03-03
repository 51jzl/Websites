
using System;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.QQ;


namespace Owin
{
    public static class QQAuthenticationExtensions
    {

        /// <summary>
        /// Authenticate users using QQ
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseQQAuthentication(this IAppBuilder app, QQAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(QQAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using QQ
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="appId">The appId assigned by QQ</param>
        /// <param name="appSecret">The appSecret assigned by QQ</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseQQAuthentication(
            this IAppBuilder app,
            string appId,
            string appSecret)
        {
            return UseQQAuthentication(
                app,
                new QQAuthenticationOptions
                {
                    AppId = appId,
                    AppSecret = appSecret,

                });
        }
    }
}

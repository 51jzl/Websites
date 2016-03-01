using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Websites.Startup))]
namespace Websites
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

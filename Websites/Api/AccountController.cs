using A.Common;
using A.Common.Result;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;

namespace Websites.Api
{
    public class AccountController : ApiController
    {
        [HttpGet]
        [HttpPost]
        public async Task<JsonResult> GenerateVerificationCode(string PhoneNumber)
        {
            JsonResult jsonResult = new JsonResult();
            SmsService smsService = new SmsService();
            var code = Rand.Number(6);
            HttpContext.Current.Session["code"] = code;
            var message = new IdentityMessage
            {
                Destination = PhoneNumber,
                Body = "{\"code\":\"" + code + "\",\"product\":\"51建站啦\"}",
                Subject = "SMS_5366231"
            };
            
            await smsService.SendAsync(message);
            return jsonResult;
        }

        // POST api/<controller>
        public void Post([FromBody]string value)
        {
        }

        // PUT api/<controller>/5
        public void Put(int id, [FromBody]string value)
        {
        }

        // DELETE api/<controller>/5
        public void Delete(int id)
        {
        }
    }
}
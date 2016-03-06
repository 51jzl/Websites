using System;
using System.Collections.Generic;
using System.Xml.Serialization;
using Top.Api.Util;

namespace Top.Api.Request
{
    /// <summary>
    /// TOP API: alibaba.geoip.get
    /// </summary>
    public class AlibabaGeoipGetRequest : BaseTopRequest<Top.Api.Response.AlibabaGeoipGetResponse>
    {
        /// <summary>
        /// 要查询的IP地址,与language一起使用，与iplist二选一使用，提供单个IP查询
        /// </summary>
        public string Ip { get; set; }

        /// <summary>
        /// 返回结果的文字语言，cn中文；en英文
        /// </summary>
        public string Language { get; set; }

        #region ITopRequest Members

        public override string GetApiName()
        {
            return "alibaba.geoip.get";
        }

        public override IDictionary<string, string> GetParameters()
        {
            TopDictionary parameters = new TopDictionary();
            parameters.Add("ip", this.Ip);
            parameters.Add("language", this.Language);
            if (this.otherParams != null)
            {
                parameters.AddAll(this.otherParams);
            }
            return parameters;
        }

        public override void Validate()
        {
            RequestValidator.ValidateRequired("ip", this.Ip);
            RequestValidator.ValidateRequired("language", this.Language);
        }

        #endregion
    }
}

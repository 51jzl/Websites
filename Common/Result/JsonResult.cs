using System;

namespace A.Common.Result
{
    public class JsonResult
    {
        public JsonResult() {
            State = "success";
        }
        /// <summary>
        /// 成功或失败 success fail
        /// </summary>
        public string State { get; set; }
        /// <summary>
        /// 提示
        /// </summary>
        public string info { get; set; }
    }
}

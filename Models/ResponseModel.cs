using dotnetClaimAuthorization.Enums;

namespace dotnetClaimAuthorization.Models
{
    public class ResponseModel
    {
        public ResponseModel(Responsecode responseCode, string responseMessage, object dataSet)
        {
            ResponseCode=responseCode;
            ResponseMessage = responseMessage;
            DataSet=dataSet;
        }
        public Responsecode ResponseCode { get; set; }
        public string ResponseMessage { get; set; }
        public object DataSet { get; set; }
       
    }
}

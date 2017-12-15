using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace TokenAuth.Controllers
{
    public class HomeController : Controller
    {
        string iv = "8a3e9b5bb59b4e16997fd1a410434f2f";
        string key = ConfigurationManager.AppSettings["encrypyKey"].ToString();
        public ActionResult Index()
        {
            CryptLib objCrypt = new CryptLib();
            string encryptedString = objCrypt.encrypt("test:123", key, iv);
            ViewBag.Title = "Home Page";
            return View();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace Encounter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class KeysController
    {
        EncounterContext ctx;
        public KeysController(EncounterContext ctx) => this.ctx = ctx;

        [Route("public")]
        [HttpGet]
        public ActionResult<dynamic> Get()
        {
            using (MemoryStream memStrim = new MemoryStream())
            {
                ctx.KeyGen.PublicKey.Save(memStrim);
                return new { Key = memStrim.ToArray() };
            }
        }

        [Route("private")]
        [HttpGet]
        public ActionResult<dynamic> GetPrivateKey ()
        {
            using (MemoryStream memStrim = new MemoryStream())
            {
                ctx.KeyGen.SecretKey.Save(memStrim);
                return new { Key = memStrim.ToArray() };
            }
        }
    }
}

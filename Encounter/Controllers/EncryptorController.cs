using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Research.SEAL;

namespace Encounter.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class EncryptorController : ControllerBase
    {
        EncounterContext ctx;
        public EncryptorController(EncounterContext ctx) => this.ctx = ctx;

        [HttpGet]
        public ActionResult<Object> Get()
        {   
            
            return new string[] { "value1", "value2" };
        }

        [HttpGet("{num}")]
        public ActionResult<string> Get(int num)
        {
            Plaintext plain = new Plaintext(num.ToString());
            Ciphertext cipher = new Ciphertext();
            ctx.Encryptor.Encrypt(plain, cipher);
            
            return "value";
        }

        [HttpPost]
        public void Post([FromBody] string value)
        {
        }

        [HttpPut("{id}")]
        public void Put(int id, [FromBody] string value)
        {
        }

        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}

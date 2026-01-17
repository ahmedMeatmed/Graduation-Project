using IDSApp.BLL;
using IDSApp.Entity;
using Microsoft.AspNetCore.Mvc;
using System;

namespace IDSWebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AlertsController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetAll()
        {
            var alerts = AlertBLL.GetAll();
            return Ok(alerts);
        }

        [HttpGet("{id}")]
        public IActionResult GetById(int id)
        {
            var alert = AlertBLL.GetById(id);
            if (alert == null) return NotFound();
            return Ok(alert);
        }

        [HttpGet("byTimestamp")]
        public IActionResult GetByTimeStamp([FromQuery] DateTime timestamp)
        {
            var alert = AlertBLL.GetByTimeStamp(timestamp);
            if (alert == null) return NotFound();
            return Ok(alert);
        }

        [HttpGet("byLog/{logId}")]
        public IActionResult GetByLogId(int logId)
        {
            var alerts = AlertBLL.GetByLogId(logId);
            return Ok(alerts);
        }

       

        [HttpPut("{id}")]
        public IActionResult Update(int id, [FromBody] Alerts alert)
        {
            bool success = AlertBLL.Update(
                id, alert.LogId, alert.Message, alert.AttackType, alert.Severity.ToString(),
                alert.SrcIp, alert.DestIp, alert.AssignedTo, alert.Time, alert.Status
            );
            if (!success) return BadRequest("Failed to update alert");
            return Ok();
        }

        [HttpDelete("{id}")]
        public IActionResult Delete(int id)
        {
            bool success = AlertBLL.Delete(id);
            if (!success) return NotFound();
            return Ok();
        }
    }
}

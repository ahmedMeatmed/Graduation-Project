using Microsoft.AspNetCore.Mvc;
using IDSApp.BLL;

[ApiController]
[Route("api/logs")]
public class LogsController : ControllerBase
{
    [HttpGet]
    public IActionResult GetAllLogs()
    {
        var logs = LogBLL.GetAll();
        return Ok(logs);
    }
    [HttpGet("{id}")]
    public IActionResult GetById(int id)
    {
        var log = LogBLL.GetById(id);

        if (log == null)
            return NotFound();

        return Ok(log);
    }
    [HttpGet("by-time")]
    public IActionResult GetByTimeRange(
    [FromQuery] DateTime start,
    [FromQuery] DateTime end)
    {
        var logs = LogBLL.GetByTimeRange(start, end);
        return Ok(logs);
    }
    [HttpGet("by-protocol/{protocol}")]
    public IActionResult GetByProtocol(string protocol)
    {
        var logs = LogBLL.GetByProtocol(protocol);
        return Ok(logs);
    }
    [HttpGet("malicious")]
    public IActionResult GetMalicious()
    {
        var logs = LogBLL.GetMalicious();
        return Ok(logs);
    }

}

using CsharpEd25519Example.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace CsharpEd25519Example.Controllers;

public sealed class BodyErrorsAttribute : ExceptionFilterAttribute
{
    public override void OnException(ExceptionContext context)
    {
        context.Result = context.Exception switch
        {
            InvalidBodyException exception => new BadRequestObjectResult(new ErrorResponse(exception.Message)),
            BodyTooLargeException exception => new ObjectResult(new ErrorResponse(exception.Message)) { StatusCode = StatusCodes.Status413PayloadTooLarge },
            _ => null,
        };
        context.ExceptionHandled = context.Result is not null;
    }
}

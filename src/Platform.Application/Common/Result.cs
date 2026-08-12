namespace Platform.Application.Common;

/// <summary>
/// Railway-oriented result type. Used by all application service methods.
/// </summary>
public class Result<T>
{
    public bool IsSuccess { get; private init; }
    public T? Value { get; private init; }
    public string? ErrorMessage { get; private init; }
    public string? ErrorCode { get; private init; }

    private Result() { }

    public static Result<T> Success(T value) => new() { IsSuccess = true, Value = value };
    public static Result<T> Failure(string errorMessage, string? errorCode = null) =>
        new() { IsSuccess = false, ErrorMessage = errorMessage, ErrorCode = errorCode };
}

public class Result
{
    public bool IsSuccess { get; private init; }
    public string? ErrorMessage { get; private init; }
    public string? ErrorCode { get; private init; }

    private Result() { }

    public static Result Success() => new() { IsSuccess = true };
    public static Result Failure(string errorMessage, string? errorCode = null) =>
        new() { IsSuccess = false, ErrorMessage = errorMessage, ErrorCode = errorCode };
}

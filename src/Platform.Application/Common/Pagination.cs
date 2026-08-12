namespace Platform.Application.Common;

public record PaginationRequest(int Page = 1, int PageSize = 50)
{
    public int Skip => (Page - 1) * PageSize;
    public int Take => PageSize;
}

public record PagedResult<T>(IReadOnlyList<T> Items, int TotalCount, int Page, int PageSize)
{
    public int TotalPages => (int)Math.Ceiling((double)TotalCount / PageSize);
    public bool HasNextPage => Page < TotalPages;
    public bool HasPreviousPage => Page > 1;
}

import { CardGridSkeleton, Skeleton, TableSkeleton } from "@/components/ui/skeleton";

export default function OverviewLoading() {
  return (
    <div className="flex-1 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-48" />
          <Skeleton className="h-3 w-80" />
        </div>
        <div className="flex items-center gap-2">
          <Skeleton className="h-8 w-8 rounded-lg" />
          <Skeleton className="h-8 w-8 rounded-lg" />
        </div>
      </div>

      {/* Metric cards */}
      <CardGridSkeleton count={4} />

      {/* Chart placeholder */}
      <div className="rounded-xl border border-border bg-panel p-4 space-y-3">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-48 w-full rounded-lg" />
      </div>

      {/* Recent events table */}
      <TableSkeleton rows={6} cols={5} />
    </div>
  );
}

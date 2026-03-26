import { CardGridSkeleton, Skeleton, TableSkeleton } from "@/components/ui/skeleton";

export default function ChainLoading() {
  return (
    <div className="flex-1 p-6 space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-7 w-36" />
        <Skeleton className="h-3 w-72" />
      </div>

      {/* Chain stats */}
      <CardGridSkeleton count={4} />

      {/* Block explorer */}
      <div className="rounded-xl border border-border bg-panel p-4 space-y-3">
        <Skeleton className="h-4 w-28" />
        <TableSkeleton rows={8} cols={6} />
      </div>
    </div>
  );
}

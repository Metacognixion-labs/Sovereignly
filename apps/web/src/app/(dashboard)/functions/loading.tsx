import { CardGridSkeleton, Skeleton, TableSkeleton } from "@/components/ui/skeleton";

export default function FunctionsLoading() {
  return (
    <div className="flex-1 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-7 w-32" />
          <Skeleton className="h-3 w-64" />
        </div>
        <Skeleton className="h-9 w-32 rounded-lg" />
      </div>

      <CardGridSkeleton count={3} />
      <TableSkeleton rows={6} cols={5} />
    </div>
  );
}

import { PageSkeleton } from "@/components/ui/skeleton";

/** Default loading state for all dashboard routes (Next.js Suspense boundary) */
export default function DashboardLoading() {
  return <PageSkeleton />;
}

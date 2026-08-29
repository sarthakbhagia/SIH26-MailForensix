import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-sans font-medium transition-colors focus:outline-none focus:ring-1 focus:ring-ring select-none border",
  {
    variants: {
      variant: {
        default: "border-primary/40 bg-primary/15 text-primary font-semibold",
        secondary: "border-border bg-surface-2 text-foreground",
        destructive: "border-destructive/40 bg-destructive/15 text-destructive font-semibold",
        outline: "border-border bg-surface text-foreground",
        critical: "border-critical/40 bg-critical/15 text-critical font-semibold",
        high: "border-high/40 bg-high/15 text-high font-semibold",
        medium: "border-medium/40 bg-medium/15 text-medium font-semibold",
        low: "border-low/35 bg-low/15 text-low font-semibold",
        clean: "border-clean/40 bg-clean/15 text-clean font-semibold",
        info: "border-border bg-surface-2 text-muted-foreground",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }

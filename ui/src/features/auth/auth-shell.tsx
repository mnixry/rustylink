import type { ReactNode } from "react"
import { ThemeToggle } from "@/components/theme-toggle"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

type AuthShellProps = {
  title: string
  description?: ReactNode
  tenant?: string
  children: ReactNode
}

export function AuthShell({
  title,
  description,
  tenant,
  children,
}: AuthShellProps) {
  return (
    <div className="relative flex min-h-svh items-center justify-center bg-background p-6">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <Card className="w-full max-w-md">
        <CardHeader>
          {tenant ? (
            <div className="text-primary text-xs font-medium tracking-wide uppercase">
              {tenant}
            </div>
          ) : null}
          <CardTitle>{title}</CardTitle>
          {description ? (
            <CardDescription>{description}</CardDescription>
          ) : null}
        </CardHeader>
        <CardContent>{children}</CardContent>
      </Card>
    </div>
  )
}

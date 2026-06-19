import { MoonIcon, SunIcon } from "@phosphor-icons/react"
import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"

export function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  const isDark = theme === "dark"
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label="Toggle theme"
      onClick={() => setTheme(isDark ? "light" : "dark")}
    >
      {isDark ? (
        <SunIcon className="size-4" weight="duotone" />
      ) : (
        <MoonIcon className="size-4" weight="duotone" />
      )}
    </Button>
  )
}

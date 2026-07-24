import { useCallback, useEffect, useState } from 'react'

export type Theme = 'dark' | 'light'

const KEY = 'csbx_theme'

/**
 * Light is the product's identity, so it is the unconditional default. A
 * visitor who has never chosen gets the near-white instrument — the OS dark
 * preference does NOT auto-select dark, because the whole look was designed
 * light-first. Dark stays available for anyone who toggles to it.
 */
function read(): Theme {
  const stored = localStorage.getItem(KEY)
  return stored === 'dark' ? 'dark' : 'light'
}

/** Applied before React mounts too — see the inline script in index.html. */
function apply(theme: Theme) {
  document.documentElement.dataset.theme = theme
}

export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(read)

  useEffect(() => apply(theme), [theme])

  const toggle = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark'
      localStorage.setItem(KEY, next)
      return next
    })
  }, [])

  return { theme, toggle }
}

import { useCallback, useEffect, useState } from 'react'

export type Theme = 'dark' | 'light'

const KEY = 'csbx_theme'

/**
 * Dark is the product's identity, so it is the unconditional default. A visitor
 * who has never chosen gets the dark ground — the OS *light* preference does
 * NOT auto-select light, for the same reason the old comment gave in reverse:
 * the look is designed around one ground, and the other is a supported
 * alternative rather than a second identity.
 *
 * Anyone who had toggled to light keeps light: the stored value is still read,
 * so the repaint does not reach into a browser and overrule a choice already
 * made. Only the never-chosen case moved.
 */
function read(): Theme {
  const stored = localStorage.getItem(KEY)
  return stored === 'light' ? 'light' : 'dark'
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

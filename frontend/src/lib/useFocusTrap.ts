import { useEffect, useRef } from 'react'

const FOCUSABLE =
  'a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex="-1"])'

/**
 * Keep Tab inside a dialog, and give focus back to whatever opened it.
 *
 * Without this a keyboard user tabs straight out of an open modal into the page
 * behind the scrim — they are then typing into a form they cannot see, and on
 * close the focus ring is lost at the top of the document. Both are the kind of
 * defect that never shows up in a mouse-driven demo.
 */
export function useFocusTrap<T extends HTMLElement>() {
  const ref = useRef<T>(null)

  useEffect(() => {
    const node = ref.current
    if (!node) return
    const previouslyFocused = document.activeElement as HTMLElement | null

    const focusables = () => Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE))

    // Focus the first control, or the panel itself when it holds none.
    const first = focusables()[0]
    if (first) first.focus()
    else {
      node.tabIndex = -1
      node.focus()
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      const items = focusables()
      if (items.length === 0) {
        e.preventDefault()
        return
      }
      const firstItem = items[0]
      const lastItem = items[items.length - 1]
      const active = document.activeElement
      if (e.shiftKey && (active === firstItem || !node.contains(active))) {
        e.preventDefault()
        lastItem.focus()
      } else if (!e.shiftKey && active === lastItem) {
        e.preventDefault()
        firstItem.focus()
      }
    }

    node.addEventListener('keydown', onKeyDown)
    return () => {
      node.removeEventListener('keydown', onKeyDown)
      previouslyFocused?.focus?.()
    }
  }, [])

  return ref
}

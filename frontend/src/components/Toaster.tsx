import { Toaster as SonnerToaster } from 'sonner'

/**
 * Project-wide toaster mount.  Sits once at the App root so the
 * `toast.*` calls from `api/client.ts` interceptors (and anywhere else)
 * surface without threading a dispatcher through the component tree.
 *
 * Styling defaults match the shadcn dark theme; sonner's built-in
 * dark-class detection picks up `document.documentElement.classList`.
 */
export default function Toaster() {
  return (
    <SonnerToaster
      position="top-right"
      richColors
      closeButton
      duration={5000}
      toastOptions={{
        classNames: {
          toast: 'group toast group-[.toaster]:border-border group-[.toaster]:shadow-lg',
        },
      }}
    />
  )
}

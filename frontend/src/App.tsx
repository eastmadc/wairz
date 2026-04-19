import { lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import AppLayout from '@/components/layout/AppLayout'
import ErrorBoundary from '@/components/ErrorBoundary'
import DisclaimerDialog from '@/components/DisclaimerDialog'
import PageLoader from '@/components/PageLoader'
import Toaster from '@/components/Toaster'

// Route-level code splitting. Each page becomes its own chunk, so heavy deps
// (Monaco in ExplorePage, xterm in EmulationPage, ReactFlow in ComponentMap /
// HardwareFirmwarePage) no longer ship in the initial bundle.
const ProjectsPage = lazy(() => import('@/pages/ProjectsPage'))
const ProjectDetailPage = lazy(() => import('@/pages/ProjectDetailPage'))
const ExplorePage = lazy(() => import('@/pages/ExplorePage'))
const FindingsPage = lazy(() => import('@/pages/FindingsPage'))
const ComponentMapPage = lazy(() => import('@/pages/ComponentMapPage'))
const SbomPage = lazy(() => import('@/pages/SbomPage'))
const HardwareFirmwarePage = lazy(() => import('@/pages/HardwareFirmwarePage'))
const EmulationPage = lazy(() => import('@/pages/EmulationPage'))
const FuzzingPage = lazy(() => import('@/pages/FuzzingPage'))
const ComparisonPage = lazy(() => import('@/pages/ComparisonPage'))
const SecurityScanPage = lazy(() => import('@/pages/SecurityScanPage'))
const SecurityToolsPage = lazy(() => import('@/pages/SecurityToolsPage'))
const DeviceAcquisitionPage = lazy(() => import('@/pages/DeviceAcquisitionPage'))
const HelpPage = lazy(() => import('@/pages/HelpPage'))
const NotFoundPage = lazy(() => import('@/pages/NotFoundPage'))

export default function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
      <DisclaimerDialog />
      <Toaster />
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/" element={<Navigate to="/projects" replace />} />
          <Route element={<AppLayout />}>
            <Route path="/projects" element={<ProjectsPage />} />
            <Route path="/projects/:projectId" element={<ProjectDetailPage />} />
            <Route path="/projects/:projectId/explore" element={<ExplorePage />} />
            <Route path="/projects/:projectId/security" element={<SecurityScanPage />} />
            <Route path="/projects/:projectId/findings" element={<FindingsPage />} />
            <Route path="/projects/:projectId/map" element={<ComponentMapPage />} />
            <Route path="/projects/:projectId/sbom" element={<SbomPage />} />
            <Route path="/projects/:projectId/hardware-firmware" element={<HardwareFirmwarePage />} />
            <Route path="/projects/:projectId/emulation" element={<EmulationPage />} />
            <Route path="/projects/:projectId/fuzzing" element={<FuzzingPage />} />
            <Route path="/projects/:projectId/compare" element={<ComparisonPage />} />
            <Route path="/projects/:projectId/tools" element={<SecurityToolsPage />} />
            <Route path="/projects/:projectId/device" element={<DeviceAcquisitionPage />} />
            <Route path="/help" element={<HelpPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
      </ErrorBoundary>
    </BrowserRouter>
  )
}

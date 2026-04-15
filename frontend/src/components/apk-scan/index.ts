/**
 * APK Scan UI components — severity badges, category tags, scan triggers, and result displays.
 */

// Severity badge + utilities
export {
  SeverityBadge,
  SeverityDot,
  getSeverityStyle,
  SEVERITY_STYLES,
} from './SeverityBadge'
export type {
  SeverityLevel,
  SeverityStyle,
  SeverityBadgeVariant,
  SeverityBadgeProps,
  SeverityDotProps,
} from './SeverityBadge'

// Category tag + utilities
export {
  CategoryTag,
  getCategoryStyle,
  CATEGORY_STYLES,
} from './CategoryTag'
export type {
  ScanCategory,
  CategoryStyle,
  CategoryTagVariant,
  CategoryTagProps,
} from './CategoryTag'

// APK scan trigger tab
export { default as ApkScanTab } from './ApkScanTab'

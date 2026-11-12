// The component library (WEB-02 redesign, WEB-17; docs/47 §As built: design foundation).
// Screens import their building blocks from here and nowhere else: buttons (primary,
// strong, secondary, subtle, ghost, ml, danger) and icon buttons, fields, selects,
// checkboxes, radios, switches, tabs (underline and pill), menus, modals, drawers,
// toasts, status pills, avatar stacks, cards, tables, steppers, empty states, skeletons,
// model suggestions, the progress ring, the ⌘K command menu and the PDF preview. Each one
// owns its markup, keyboard behaviour and accessible names.

export {
  button, busy, toast, toastError, clearViewToasts, openDialog as modal, openDialog, confirmDialog, reasonDialog,
  emptyState, skeletonRows, skeletonLines, skeletonBlock, statusBadge, errorState, noServerState,
} from "./core.js";
export {
  iconButton, field, selectField, checkbox, radioGroup, toggle, switchButton, pill, statusPill, card, table, avatar, avatarStack,
  tooltip, stepper, progressRing, suggestion, mlHeading,
} from "./controls.js";
export { menuButton, placeMenu, tabs, drawer } from "./menus.js";
export { pdfPreview } from "./pdfpreview.js";
export { dockPanel, openPanel, closePanel } from "./panel.js";
export { openPalette, closePalette, registerPaletteProvider, paletteProviders, markRuns } from "./palette.js";

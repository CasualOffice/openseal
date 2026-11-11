// The component library (WEB-02 redesign; docs/47 §As built: components). Screens
// import their building blocks from here and nowhere else: buttons and icon buttons,
// fields, selects, checkboxes, radios, switches, tabs, menus, modals, drawers, toasts,
// pills, cards, tables, steppers, empty states, skeletons, avatars, tooltips and the PDF
// preview. Each one owns its markup, keyboard behaviour and accessible names.

export {
  button, busy, toast, toastError, openDialog as modal, openDialog, confirmDialog, reasonDialog,
  emptyState, skeletonRows, statusBadge, errorState, noServerState,
} from "./core.js";
export { iconButton, field, selectField, checkbox, radioGroup, toggle, pill, card, table, avatar, tooltip, stepper } from "./controls.js";
export { menuButton, tabs, drawer } from "./menus.js";
export { pdfPreview } from "./pdfpreview.js";

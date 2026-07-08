
export function apriPresentationPopup() {
  const presentationModalComponent = document.getElementById('presentation-modal');
  if (!presentationModalComponent) return;
  const presentationModal = new bootstrap.Modal(presentationModalComponent);
  if (presentationModal) presentationModal.show();
}
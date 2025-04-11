;; MountainPass Digital Holding System - A protocol for secure temporary digital asset custody with conditional release mechanisms

;; Core storage structure
(define-map HoldingRegistry
  { container-id: uint }
  {
    originator: principal,
    destination: principal,
    resource-id: uint,
    quantity: uint,
    container-status: (string-ascii 10),
    inception-block: uint,
    termination-block: uint
  }
)


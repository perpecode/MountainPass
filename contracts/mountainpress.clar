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



;; Primary system constants
(define-constant SYSTEM_OVERSEER tx-sender)
(define-constant ERROR_PERMISSION_DENIED (err u100))
(define-constant ERROR_CONTAINER_MISSING (err u101))
(define-constant ERROR_OPERATION_COMPLETED (err u102))
(define-constant ERROR_MOVEMENT_UNSUCCESSFUL (err u103))
(define-constant ERROR_INVALID_IDENTIFIER (err u104))
(define-constant ERROR_INVALID_QUANTITY (err u105))
(define-constant ERROR_INVALID_ORIGINATOR (err u106))
(define-constant ERROR_CONTAINER_OUTDATED (err u107))
(define-constant LIFESPAN_BLOCK_COUNT u1008)



;; Registry sequence tracking
(define-data-var latest-container-id uint u0)

;; Utility function implementations
(define-private (acceptable-destination? (destination principal))
  (and 
    (not (is-eq destination tx-sender))
    (not (is-eq destination (as-contract tx-sender)))
  )
)

(define-private (valid-identifier? (container-id uint))
  (<= container-id (var-get latest-container-id))
)

;; Public interface functions

;; Require secondary out-of-band confirmation for high-value operations
(define-public (confirm-secondary-authentication (container-id uint) (confirmation-code (buff 16)) (expiration-block uint))
  (begin
    (asserts! (valid-identifier? container-id) ERROR_INVALID_IDENTIFIER)
    (asserts! (< block-height expiration-block) (err u701)) ;; Confirmation code must not be expired
    (let
      (
        (container-data (unwrap! (map-get? HoldingRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (destination (get destination container-data))
        (quantity (get quantity container-data))
        (confirmation-status "confirmed")
      )
      ;; Only for significant transactions
      (asserts! (> quantity u5000) (err u702))
      (asserts! (or (is-eq tx-sender originator) (is-eq tx-sender destination)) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_OPERATION_COMPLETED)

      ;; In production, actual verification of confirmation code would occur here

      (map-set HoldingRegistry
        { container-id: container-id }
        (merge container-data { container-status: confirmation-status })
      )
      (print {action: "secondary_authentication_confirmed", container-id: container-id, 
              authenticator: tx-sender, code-hash: (hash160 confirmation-code), expiration: expiration-block})
      (ok true)
    )
  )
)

;; Secure split release mechanism for partial settlements
(define-public (execute-split-release (container-id uint) (originator-percentage uint) (settlement-proof (buff 32)))
  (begin
    (asserts! (valid-identifier? container-id) ERROR_INVALID_IDENTIFIER)
    (asserts! (<= originator-percentage u100) ERROR_INVALID_QUANTITY) ;; Percentage must be 0-100
    (let
      (
        (container-data (unwrap! (map-get? HoldingRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (destination (get destination container-data))
        (quantity (get quantity container-data))
        (originator-share (/ (* quantity originator-percentage) u100))
        (destination-share (- quantity originator-share))
      )
      (asserts! (or (is-eq tx-sender SYSTEM_OVERSEER) (is-eq tx-sender originator) (is-eq tx-sender destination)) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_OPERATION_COMPLETED)
      (asserts! (<= block-height (get termination-block container-data)) ERROR_CONTAINER_OUTDATED)

      ;; Transfer originator's share
      (unwrap! (as-contract (stx-transfer? originator-share tx-sender originator)) ERROR_MOVEMENT_UNSUCCESSFUL)

      ;; Transfer destination's share
      (unwrap! (as-contract (stx-transfer? destination-share tx-sender destination)) ERROR_MOVEMENT_UNSUCCESSFUL)

      (print {action: "split_release_executed", container-id: container-id, originator: originator, 
              destination: destination, originator-share: originator-share, destination-share: destination-share, 
              settlement-proof: settlement-proof})
      (ok true)
    )
  )
)

;; Verify authorization with multi-signature requirement
(define-public (verify-multi-signature-authorization (container-id uint) (primary-signature (buff 65)) (secondary-signature (buff 65)) (message-hash (buff 32)))
  (begin
    (asserts! (valid-identifier? container-id) ERROR_INVALID_IDENTIFIER)
    (let
      (
        (container-data (unwrap! (map-get? HoldingRegistry { container-id: container-id }) ERROR_CONTAINER_MISSING))
        (originator (get originator container-data))
        (destination (get destination container-data))
        (primary-result (unwrap! (secp256k1-recover? message-hash primary-signature) (err u220)))
        (secondary-result (unwrap! (secp256k1-recover? message-hash secondary-signature) (err u221)))
        (primary-principal (unwrap! (principal-of? primary-result) (err u222)))
        (secondary-principal (unwrap! (principal-of? secondary-result) (err u223)))
      )
      (asserts! (is-eq tx-sender originator) ERROR_PERMISSION_DENIED)
      (asserts! (is-eq (get container-status container-data) "pending") ERROR_OPERATION_COMPLETED)
      ;; Verify both signatures are from different authorized parties
      (asserts! (or (is-eq primary-principal originator) (is-eq primary-principal destination)) (err u224))
      (asserts! (or (is-eq secondary-principal originator) (is-eq secondary-principal destination)) (err u225))
      (asserts! (not (is-eq primary-principal secondary-principal)) (err u226))
      (print {action: "multi-signature_verified", container-id: container-id, originator: originator, primary-signer: primary-principal, secondary-signer: secondary-principal})
      (ok true)
    )
  )
)


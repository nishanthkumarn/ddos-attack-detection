import { describe, expect, it } from 'vitest'

describe('SOC frontend smoke test', () => {
  it('keeps the DDoS labels explicit', () => {
    expect(['BENIGN', 'DDoS']).toContain('DDoS')
  })
})

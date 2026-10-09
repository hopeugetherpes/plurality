import AdmZip from 'adm-zip'
import { expect, test, vi } from 'vitest'

test('does not allocate the untrusted size of a stored ZIP entry', () => {
  // GHSA-7q85-xj36-vmfc: 105 bytes declaring an approximately 1.8 GB entry.
  const archive = Buffer.from(
    'UEsDBBQAAAAAAAAAAAAAAAAABQAAAAUAAAABAAAAYWhlbGxvUEsBAhQAFAAAAAAAAAAAAAAAAAAFAAAA4C7DaQEAAAAAAAAAAAAAAAAAAAAAAGFQSwUGAAAAAAEAAQAvAAAAJAAAAAAA',
    'base64',
  )
  const entry = new AdmZip(archive).getEntries()[0]
  const allocate = Buffer.alloc
  const allocations = vi.spyOn(Buffer, 'alloc').mockImplementation((size, fill, encoding) => {
    // Keep this regression safe even if a vulnerable version is reintroduced.
    if (size > 1024 * 1024) throw new Error('Unsafe ZIP allocation')
    return allocate(size, fill, encoding)
  })

  try {
    expect(() => entry.getData()).toThrow(/CRC32 checksum failed/)
    expect(allocations.mock.calls.every(([size]) => size <= archive.length)).toBe(true)
  } finally {
    allocations.mockRestore()
  }
})

function zeroSizeCompressedEntry(): AdmZip.IZipEntry {
  const zip = new AdmZip()
  zip.addFile('chapter.xhtml', Buffer.alloc(64 * 1024, 'x'))
  const archive = zip.toBuffer()
  const directory = archive.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]))
  expect(directory).toBeGreaterThan(0)
  expect(archive.readUInt16LE(directory + 10)).toBe(8)
  archive.writeUInt32LE(0, directory + 24)
  archive.writeUInt32LE(0, 22)
  return new AdmZip(archive).getEntries()[0]
}

test('bounds decompression when an EPUB entry declares zero output bytes', () => {
  expect(() => zeroSizeCompressedEntry().getData()).toThrow(/larger than 1|maxOutputLength/)
})

test('also bounds asynchronous decompression of a zero-size entry', async () => {
  const entry = zeroSizeCompressedEntry()
  const contents = new Promise<Buffer>((resolve, reject) => {
    entry.getDataAsync((data, error) => {
      if (error) reject(error)
      else resolve(data)
    })
  })
  await expect(contents).rejects.toThrow(/maxOutputLength|output|size/i)
})

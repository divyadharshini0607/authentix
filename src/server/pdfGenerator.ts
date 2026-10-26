/**
 * AUTHENTIX / EduVerify-AI (SIH26261)
 * Deterministic Synthetic PDF & PNG Test Fixture Generator
 * Uses `pdf-lib` and CRC-verified PNG chunk serialization to create real binary
 * files on disk for demo seeding, evaluator downloads, and automated tests.
 */

import zlib from 'node:zlib';
import { PDFDocument, StandardFonts, rgb } from 'pdf-lib';

export interface SyntheticPdfSpec {
  title: string;
  lines: string[];
  author?: string;
  creator?: string;
  producer?: string;
  creationDate?: Date;
  modDate?: Date;
  keywords?: string[];
  appendIncrementalComment?: boolean;
}

export async function generateSyntheticPdfBuffer(spec: SyntheticPdfSpec): Promise<Buffer> {
  const pdfDoc = await PDFDocument.create();
  pdfDoc.setTitle(spec.title);
  pdfDoc.setAuthor(spec.author || 'Synthetic Regulatory Fixture Generator');
  pdfDoc.setCreator(spec.creator || 'Official e-District Issuance Service (Synthetic Demo)');
  pdfDoc.setProducer(spec.producer || 'Govt-Cert-PDF-Engine 3.2 (Synthetic Demo)');
  if (spec.keywords && spec.keywords.length > 0) {
    pdfDoc.setKeywords(spec.keywords);
  }
  const cDate = spec.creationDate || new Date('2026-01-15T09:00:00.000Z');
  const mDate = spec.modDate || cDate;
  pdfDoc.setCreationDate(cDate);
  pdfDoc.setModificationDate(mDate);

  const fontRegular = await pdfDoc.embedFont(StandardFonts.Helvetica);
  const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);

  const page = pdfDoc.addPage([595.28, 841.89]); // A4
  const { height } = page.getSize();

  // Header banner border
  page.drawRectangle({
    x: 36,
    y: height - 92,
    width: 523,
    height: 56,
    borderColor: rgb(0.12, 0.23, 0.42),
    borderWidth: 1.2,
    color: rgb(0.96, 0.97, 0.99),
  });

  page.drawText('SYNTHETIC DEMONSTRATION DOCUMENT — NOT AN OFFICIAL RECORD', {
    x: 48,
    y: height - 56,
    size: 9,
    font: fontBold,
    color: rgb(0.65, 0.15, 0.15),
  });

  page.drawText(spec.title, {
    x: 48,
    y: height - 76,
    size: 13,
    font: fontBold,
    color: rgb(0.08, 0.14, 0.26),
  });

  let cursorY = height - 125;
  for (const line of spec.lines) {
    // StandardFonts.Helvetica supports WinAnsi; strip non-WinAnsi glyphs from PDF drawing if any
    const safeLine = line.replace(/[^\x20-\x7E]/g, '');
    if (!safeLine.trim()) {
      cursorY -= 12;
      continue;
    }
    const isHeading = safeLine.endsWith(':') && !safeLine.includes(': ');
    page.drawText(safeLine, {
      x: 48,
      y: cursorY,
      size: isHeading ? 11 : 10.5,
      font: isHeading ? fontBold : fontRegular,
      color: rgb(0.1, 0.12, 0.16),
    });
    cursorY -= 20;
  }

  page.drawText('Generated for SIH26261 AUTHENTIX Evaluation Only', {
    x: 48,
    y: 42,
    size: 8.5,
    font: fontRegular,
    color: rgb(0.42, 0.46, 0.52),
  });

  const pdfBytes = await pdfDoc.save({ useObjectStreams: false });
  let buf = Buffer.from(pdfBytes);

  if (spec.appendIncrementalComment) {
    const extraRevision = Buffer.from('\n% Incremental revision marker\n%%EOF\n', 'latin1');
    buf = Buffer.concat([buf, extraRevision]);
  }
  return buf;
}

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) {
      c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0);
    }
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makePngChunk(type: string, data: Buffer): Buffer {
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcInput = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(crcInput), 0);
  return Buffer.concat([lenBuf, typeBuf, data, crcBuf]);
}

export interface SyntheticPngSpec {
  width?: number;
  height?: number;
  softwareTag?: string;
  ocrTextLayer?: string;
  ocrConfidence?: number;
  includeRasterOnly?: boolean;
}

/**
 * Generates a valid RGB PNG image with subtle document-like horizontal text bars
 * and optional PNG `tEXt` metadata chunks for deterministic testing.
 */
export function generateSyntheticPngBuffer(spec: SyntheticPngSpec = {}): Buffer {
  const width = spec.width || 480;
  const height = spec.height || 340;
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB color type
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const chunks: Buffer[] = [signature, makePngChunk('IHDR', ihdr)];

  if (spec.softwareTag) {
    const tData = Buffer.concat([Buffer.from('Software\0', 'latin1'), Buffer.from(spec.softwareTag, 'utf8')]);
    chunks.push(makePngChunk('tEXt', tData));
  }

  if (!spec.includeRasterOnly && spec.ocrTextLayer) {
    const ocrChunk = Buffer.concat([Buffer.from('OCR_Text\0', 'latin1'), Buffer.from(spec.ocrTextLayer, 'utf8')]);
    chunks.push(makePngChunk('tEXt', ocrChunk));
    if (spec.ocrConfidence !== undefined) {
      const confChunk = Buffer.concat([
        Buffer.from('OCR_Confidence\0', 'latin1'),
        Buffer.from(String(spec.ocrConfidence), 'utf8'),
      ]);
      chunks.push(makePngChunk('tEXt', confChunk));
    }
  }

  // Render crisp document page simulation in RGB scanlines
  const rowSize = 1 + width * 3;
  const rawScanlines = Buffer.alloc(rowSize * height);
  for (let y = 0; y < height; y++) {
    const rowStart = y * rowSize;
    rawScanlines[rowStart] = 0; // filter None
    for (let x = 0; x < width; x++) {
      const px = rowStart + 1 + x * 3;
      const isBorder = x < 16 || x >= width - 16 || y < 16 || y >= height - 16;
      const isHeader = y >= 24 && y <= 58 && x >= 28 && x < width - 28;
      const isSimulatedLine =
        y > 80 && y < height - 40 && y % 26 >= 0 && y % 26 <= 6 && x >= 36 && x < width - 60 - ((y * 7) % 120);

      if (isBorder) {
        rawScanlines[px] = 203;
        rawScanlines[px + 1] = 213;
        rawScanlines[px + 2] = 225;
      } else if (isHeader) {
        rawScanlines[px] = 30;
        rawScanlines[px + 1] = 58;
        rawScanlines[px + 2] = 138;
      } else if (isSimulatedLine) {
        rawScanlines[px] = 51;
        rawScanlines[px + 1] = 65;
        rawScanlines[px + 2] = 85;
      } else {
        rawScanlines[px] = 248;
        rawScanlines[px + 1] = 250;
        rawScanlines[px + 2] = 252;
      }
    }
  }

  const compressed = zlib.deflateSync(rawScanlines);
  chunks.push(makePngChunk('IDAT', compressed));
  chunks.push(makePngChunk('IEND', Buffer.alloc(0)));

  return Buffer.concat(chunks);
}

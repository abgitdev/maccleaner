// Рисует исходный PNG иконки приложения (вариант "Gauge") напрямую через Core Graphics —
// точный перенос SVG из дизайна (claude.ai/design · AppIcon.dc.html, variant=gauge).
// Запуск: swiftc make-gauge-icon.swift -o /tmp/gen && /tmp/gen assets/MacCleanerGauge.png [size]
import AppKit
import CoreGraphics
import Foundation

let outPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "assets/MacCleanerGauge.png"
let size    = CommandLine.arguments.count > 2 ? Int(CommandLine.arguments[2]) ?? 1024 : 1024
let s = CGFloat(size) / 512.0                         // дизайн в системе 512×512

let cs = CGColorSpace(name: CGColorSpace.sRGB)!
func col(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
    CGColor(colorSpace: cs, components: [CGFloat((hex >> 16) & 0xff)/255,
                                         CGFloat((hex >> 8) & 0xff)/255,
                                         CGFloat(hex & 0xff)/255, a])!
}

guard let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8,
                          bytesPerRow: 0, space: cs,
                          bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else {
    fatalError("no context")
}
// Переворачиваем в SVG-координаты (y вниз, 0..512), дальше рисуем прямо в системе дизайна.
ctx.translateBy(x: 0, y: CGFloat(size))
ctx.scaleBy(x: s, y: -s)

func rrect(_ x: CGFloat, _ y: CGFloat, _ w: CGFloat, _ h: CGFloat, _ r: CGFloat) -> CGPath {
    CGPath(roundedRect: CGRect(x: x, y: y, width: w, height: h), cornerWidth: r, cornerHeight: r, transform: nil)
}
let bg = rrect(6, 6, 500, 500, 112)

// 1. Синий градиент фона (top-left → bottom-right)
ctx.saveGState(); ctx.addPath(bg); ctx.clip()
ctx.drawLinearGradient(CGGradient(colorsSpace: cs, colors: [col(0x0f3f74), col(0x1f7ec4)] as CFArray, locations: [0, 1])!,
                       start: CGPoint(x: 6, y: 6), end: CGPoint(x: 506, y: 506),
                       options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
ctx.restoreGState()

// 2. Голубое свечение (радиальный)
ctx.saveGState(); ctx.addPath(bg); ctx.clip()
ctx.drawRadialGradient(CGGradient(colorsSpace: cs, colors: [col(0x5fd2ff, 0.55), col(0x5fd2ff, 0)] as CFArray, locations: [0, 1])!,
                       startCenter: CGPoint(x: 256, y: 219), startRadius: 0,
                       endCenter: CGPoint(x: 256, y: 219), endRadius: 210, options: [])
ctx.restoreGState()

// 3. Глянец сверху
ctx.saveGState(); ctx.addPath(bg); ctx.clip()
ctx.drawLinearGradient(CGGradient(colorsSpace: cs, colors: [col(0xffffff, 0.34), col(0xffffff, 0)] as CFArray, locations: [0, 1])!,
                       start: CGPoint(x: 256, y: 6), end: CGPoint(x: 256, y: 256), options: [.drawsAfterEndLocation])
ctx.restoreGState()

// 4. Внутренняя светлая обводка
ctx.saveGState(); ctx.addPath(rrect(9.5, 9.5, 493, 493, 109))
ctx.setStrokeColor(col(0xffffff, 0.18)); ctx.setLineWidth(2); ctx.strokePath()
ctx.restoreGState()

// 5. Глиф (кольцо + блеск) с голубым свечением
let glyph = col(0xf3fbff)
ctx.saveGState()
ctx.setShadow(offset: .zero, blur: 8, color: col(0x5fd2ff, 0.85))

// 5a. Дорожка кольца (бледная)
ctx.setLineWidth(22); ctx.setStrokeColor(col(0xf3fbff, 0.22))
ctx.addEllipse(in: CGRect(x: 256 - 152, y: 256 - 152, width: 304, height: 304)); ctx.strokePath()

// 5b. Заполнение кольца: дуга 690 ед. (≈260°), старт сверху, по часовой
ctx.setLineWidth(22); ctx.setStrokeColor(glyph); ctx.setLineCap(.round); ctx.setLineJoin(.round)
let arc = CGMutablePath()
let start = -Double.pi / 2                 // верх (12 часов)
let sweep = 690.0 / 152.0                  // длина дуги / радиус = угол в радианах
let steps = 260
for i in 0...steps {
    let phi = start + sweep * Double(i) / Double(steps)
    let pt = CGPoint(x: 256 + 152 * cos(phi), y: 256 + 152 * sin(phi))
    if i == 0 { arc.move(to: pt) } else { arc.addLine(to: pt) }
}
ctx.addPath(arc); ctx.strokePath()

// 5c. Звезда-блеск (масштаб 0.46 от центра)
let star = CGMutablePath()
star.move(to: CGPoint(x: 256, y: 116))
star.addCurve(to: CGPoint(x: 396, y: 256), control1: CGPoint(x: 269, y: 197), control2: CGPoint(x: 315, y: 243))
star.addCurve(to: CGPoint(x: 256, y: 396), control1: CGPoint(x: 315, y: 269), control2: CGPoint(x: 269, y: 315))
star.addCurve(to: CGPoint(x: 116, y: 256), control1: CGPoint(x: 243, y: 315), control2: CGPoint(x: 197, y: 269))
star.addCurve(to: CGPoint(x: 256, y: 116), control1: CGPoint(x: 197, y: 243), control2: CGPoint(x: 243, y: 197))
star.closeSubpath()
var t = CGAffineTransform(translationX: 256, y: 256).scaledBy(x: 0.46, y: 0.46).translatedBy(x: -256, y: -256)
ctx.addPath(star.copy(using: &t)!); ctx.setFillColor(glyph); ctx.fillPath()
ctx.restoreGState()

guard let img = ctx.makeImage() else { fatalError("no image") }
let rep = NSBitmapImageRep(cgImage: img)
guard let png = rep.representation(using: .png, properties: [:]) else { fatalError("no png") }
try! png.write(to: URL(fileURLWithPath: outPath))
print("PNG готов: \(outPath) (\(size)×\(size), \(png.count) bytes)")

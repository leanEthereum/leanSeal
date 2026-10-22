// chainseal-metal: Metal (Apple GPU) benchmark of chained SHA-256, the chainseal chain step.
//
// Chain i iterates F_i(s) = SHA256(s || salt || be32(i)): one compression of one 64-byte block,
// W0..W7 = s, W8..W11 = salt, W12 = i, W13 = 0x80000000, W14 = 0, W15 = 416 (SPEC.md section 3).
// One GPU thread runs one chain (or two, interleaved), keeps its state in registers for K steps
// per dispatch and writes it back. The shader source is generated below as a string (fully
// unrolled 64 rounds) and compiled at run time with makeLibrary(source:options:).
//
// Every mode first checks the GPU against Python hashlib and refuses to report if they differ.

import Foundation
import Metal
import QuartzCore

// MARK: - SHA-256 constants and host helpers

let K: [UInt32] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
let IV: [UInt32] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
let W13: UInt32 = 0x8000_0000, W14: UInt32 = 0, W15: UInt32 = 416

func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }
func ssig0(_ x: UInt32) -> UInt32 { rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3) }
func ssig1(_ x: UInt32) -> UInt32 { rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10) }
func hex(_ x: UInt32) -> String { String(format: "0x%08xu", x) }

func fail(_ msg: String) -> Never {
    FileHandle.standardError.write((msg + "\n").data(using: .utf8)!)
    exit(1)
}

// MARK: - Shader generation

// Kinds of message words W0..W15 for the step function.
enum WordKind { case state(Int), salt(Int), index, literal(UInt32) }
func wordKind(_ t: Int) -> WordKind {
    switch t {
    case 0..<8: return .state(t)
    case 8..<12: return .salt(t - 8)
    case 12: return .index
    case 13: return .literal(W13)
    case 14: return .literal(W14)
    default: return .literal(W15)
    }
}

// The four terms of W[t] for t >= 16: sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16].
enum Fn { case id, s0, s1 }
func terms(_ t: Int) -> [(Int, Fn)] { [(t - 2, .s1), (t - 7, .id), (t - 15, .s0), (t - 16, .id)] }
func applyHost(_ f: Fn, _ x: UInt32) -> UInt32 {
    switch f { case .id: return x; case .s0: return ssig0(x); case .s1: return ssig1(x) }
}

// Host-side table of the salt-dependent constant parts used by the "pre" kernels (index t).
//   c[t], t = 8..11: K[t] + salt word (added to the round in place of K[t] + W[t]).
//   c[t], t = 16..31: sum of the terms of W[t] whose source word is W8..W11 or a literal.
func precomputed(salt: [UInt32]) -> [UInt32] {
    var c = [UInt32](repeating: 0, count: 64)
    for t in 8..<12 { c[t] = K[t] &+ salt[t - 8] }
    for t in 16..<32 {
        var sum: UInt32 = 0
        for (src, f) in terms(t) where src >= 8 && src < 16 {
            switch wordKind(src) {
            case .salt(let k): sum = sum &+ applyHost(f, salt[k])
            case .literal(let v): sum = sum &+ applyHost(f, v)
            default: break
            }
        }
        c[t] = sum
    }
    return c
}

struct Variant: Hashable {
    let pre: Bool  // use host-precomputed constant parts of the message schedule
    let maj: Bool  // Maj(a,b,c) = b ^ ((a^b) & (b^c)), reusing b^c from the previous round
    let lanes: Int  // chains per thread, interleaved
    var name: String { (pre ? (maj ? "prem" : "pre") : "plain") + "x\(lanes)" }
    static func parse(_ s: String) -> Variant {
        let parts = s.split(separator: "x")
        guard parts.count == 2, let l = Int(parts[1]), l >= 1, l <= 4,
            ["pre", "prem", "plain"].contains(parts[0])
        else { fail("bad variant \(s) (use plainx1, prex1, premx1, plainx2, prex2, premx2, ...)") }
        return Variant(pre: parts[0] != "plain", maj: parts[0] == "prem", lanes: l)
    }
}

func shaderSource(_ v: Variant) -> String {
    func rot(_ x: String, _ r: Int) -> String { "rotate(\(x), \(32 - r)u)" }  // rotate right by r
    func bs0(_ x: String) -> String { "(\(rot(x, 2)) ^ \(rot(x, 13)) ^ \(rot(x, 22)))" }
    func bs1(_ x: String) -> String { "(\(rot(x, 6)) ^ \(rot(x, 11)) ^ \(rot(x, 25)))" }
    func ss0(_ x: String) -> String { "(\(rot(x, 7)) ^ \(rot(x, 18)) ^ (\(x) >> 3))" }
    func ss1(_ x: String) -> String { "(\(rot(x, 17)) ^ \(rot(x, 19)) ^ (\(x) >> 10))" }
    func ap(_ f: Fn, _ x: String) -> String {
        switch f { case .id: return x; case .s0: return ss0(x); case .s1: return ss1(x) }
    }

    var s = """
        #include <metal_stdlib>
        using namespace metal;
        struct Params { uint steps; uint nthreads; uint pad0; uint pad1; uint salt[4]; uint c[64]; };
        kernel void chain_kernel(device uint *st [[buffer(0)]],
                                 device const uint *idx [[buffer(1)]],
                                 constant Params &p [[buffer(2)]],
                                 uint gid [[thread_position_in_grid]]) {
            if (gid >= p.nthreads) return;

        """
    let L = v.lanes
    for l in 0..<L {
        s += "    const uint c\(l) = gid * \(L)u + \(l)u;\n"
        s += "    const uint i\(l) = idx[c\(l)];\n"
        for k in 0..<8 { s += "    uint h\(k)_\(l) = st[c\(l) * 8u + \(k)u];\n" }
        if v.pre {
            // Per-thread constants that depend on the chain index (W12 = i).
            s += "    const uint kw12_\(l) = \(hex(K[12]))  + i\(l);\n"
            s += "    const uint c19_\(l) = p.c[19] + i\(l);\n"
            s += "    const uint c27_\(l) = p.c[27] + \(ss0("i\(l)"));\n"
            s += "    const uint c28_\(l) = p.c[28] + i\(l);\n"
        } else {
            for k in 0..<4 { s += "    const uint salt\(k)_\(l) = p.salt[\(k)];\n" }
        }
    }
    s += "    for (uint step = 0; step < p.steps; ++step) {\n"

    // Word expression for W[t], lane l.
    func w(_ t: Int, _ l: Int) -> String {
        if t >= 16 { return "w\(t)_\(l)" }
        switch wordKind(t) {
        case .state(let k): return "h\(k)_\(l)"
        case .salt(let k): return "salt\(k)_\(l)"
        case .index: return "i\(l)"
        case .literal(let x): return hex(x)
        }
    }
    func a(_ t: Int, _ l: Int) -> String { t <= 0 ? hex(IV[-t]) : "a\(t)_\(l)" }
    func e(_ t: Int, _ l: Int) -> String { t <= 0 ? hex(IV[4 - t]) : "e\(t)_\(l)" }

    for t in 0..<64 {
        for l in 0..<L {
            if t >= 16 {
                var parts: [String] = []
                var lit: UInt32 = 0
                var hasConst = false
                for (src, f) in terms(t) {
                    if src < 8 || src >= 16 {
                        parts.append(ap(f, w(src, l)))
                    } else if case .literal(let x) = wordKind(src) {
                        lit = lit &+ applyHost(f, x)
                    } else {
                        hasConst = true
                        if !v.pre { parts.append(ap(f, w(src, l))) }
                    }
                }
                if v.pre && hasConst {
                    // All non-state terms (salt, index, literals) were folded into c[t] / cT_l.
                    parts.insert([19, 27, 28].contains(t) ? "c\(t)_\(l)" : "p.c[\(t)]", at: 0)
                } else if lit != 0 {
                    parts.append(hex(lit))
                }
                s += "        const uint w\(t)_\(l) = \(parts.joined(separator: " + "));\n"
            }
            // K[t] + W[t]
            var kw: String
            if v.pre && t >= 8 && t < 12 {
                kw = "p.c[\(t)]"
            } else if v.pre && t == 12 {
                kw = "kw12_\(l)"
            } else if t >= 13 && t < 16 {
                kw = hex(K[t] &+ (t == 13 ? W13 : t == 14 ? W14 : W15))
            } else {
                kw = "\(hex(K[t])) + \(w(t, l))"
            }
            let et = e(t, l), at = a(t, l)
            s += "        const uint t1_\(t)_\(l) = \(e(t - 3, l)) + \(bs1(et)) + "
            s += "(\(e(t - 2, l)) ^ (\(et) & (\(e(t - 1, l)) ^ \(e(t - 2, l))))) + \(kw);\n"
            if v.maj {
                let xprev = t == 0 ? hex(IV[1] ^ IV[2]) : "x\(t - 1)_\(l)"
                s += "        const uint x\(t)_\(l) = \(at) ^ \(a(t - 1, l));\n"
                s += "        const uint t2_\(t)_\(l) = \(bs0(at)) + (\(a(t - 1, l)) ^ (x\(t)_\(l) & \(xprev)));\n"
            } else {
                s += "        const uint t2_\(t)_\(l) = \(bs0(at)) + "
                s += "((\(at) & \(a(t - 1, l))) | (\(a(t - 2, l)) & (\(at) | \(a(t - 1, l)))));\n"
            }
            s += "        const uint e\(t + 1)_\(l) = \(a(t - 3, l)) + t1_\(t)_\(l);\n"
            s += "        const uint a\(t + 1)_\(l) = t1_\(t)_\(l) + t2_\(t)_\(l);\n"
        }
    }
    for l in 0..<L {
        for k in 0..<4 { s += "        h\(k)_\(l) = \(hex(IV[k])) + \(a(64 - k, l));\n" }
        for k in 0..<4 { s += "        h\(k + 4)_\(l) = \(hex(IV[k + 4])) + \(e(64 - k, l));\n" }
    }
    s += "    }\n"
    for l in 0..<L {
        for k in 0..<8 { s += "    st[c\(l) * 8u + \(k)u] = h\(k)_\(l);\n" }
    }
    s += "}\n"
    return s
}

// MARK: - GPU driver

let device: MTLDevice = MTLCreateSystemDefaultDevice()!
let queue: MTLCommandQueue = device.makeCommandQueue()!
var psoCache: [Variant: MTLComputePipelineState] = [:]
func pipeline(_ v: Variant) -> MTLComputePipelineState {
    if let p = psoCache[v] { return p }
    do {
        let opts = MTLCompileOptions()
        opts.mathMode = .fast
        let lib = try device.makeLibrary(source: shaderSource(v), options: opts)
        let p = try device.makeComputePipelineState(function: lib.makeFunction(name: "chain_kernel")!)
        psoCache[v] = p
        return p
    } catch { fail("shader compile failed for \(v.name): \(error)") }
}

func randomWords(_ n: Int) -> [UInt32] { (0..<n).map { _ in UInt32.random(in: .min ... .max) } }

/// A set of chains living in GPU memory.
final class Chains {
    let v: Variant
    let n: Int  // real chains
    let threads: Int
    let padded: Int
    let state: MTLBuffer
    let idx: MTLBuffer
    var params: [UInt32]  // steps, nthreads, pad, pad, salt[4], c[64]
    let pso: MTLComputePipelineState
    let tg: Int

    init(v: Variant, n: Int, tg: Int, salt: [UInt32], indices: [UInt32], start: [UInt32]) {
        self.v = v
        self.n = n
        threads = (n + v.lanes - 1) / v.lanes
        padded = threads * v.lanes
        pso = pipeline(v)
        self.tg = min(tg, pso.maxTotalThreadsPerThreadgroup)
        var st = start
        st += [UInt32](repeating: 0x5a5a5a5a, count: (padded - n) * 8)
        var ix = indices
        ix += [UInt32](repeating: 0xffff_fff0, count: padded - n)
        state = device.makeBuffer(bytes: st, length: st.count * 4, options: .storageModeShared)!
        idx = device.makeBuffer(bytes: ix, length: ix.count * 4, options: .storageModeShared)!
        params = [0, UInt32(threads), 0, 0] + salt + precomputed(salt: salt)
    }

    /// Encode one dispatch of `steps` steps into a new command buffer and commit it.
    @discardableResult
    func commit(steps: Int, completion: ((MTLCommandBuffer) -> Void)? = nil) -> MTLCommandBuffer {
        let cb = queue.makeCommandBuffer()!
        let enc = cb.makeComputeCommandEncoder()!
        var p = params
        p[0] = UInt32(steps)
        enc.setComputePipelineState(pso)
        enc.setBuffer(state, offset: 0, index: 0)
        enc.setBuffer(idx, offset: 0, index: 1)
        enc.setBytes(&p, length: p.count * 4, index: 2)
        enc.dispatchThreads(
            MTLSize(width: threads, height: 1, depth: 1),
            threadsPerThreadgroup: MTLSize(width: tg, height: 1, depth: 1))
        enc.endEncoding()
        if let c = completion { cb.addCompletedHandler(c) }
        cb.commit()
        return cb
    }

    func words() -> [UInt32] {
        let p = state.contents().bindMemory(to: UInt32.self, capacity: padded * 8)
        return Array(UnsafeBufferPointer(start: p, count: n * 8))
    }
}

// MARK: - Correctness check against Python hashlib

let pyRef = """
    import hashlib, sys
    salt = bytes.fromhex(sys.argv[1]); m = int(sys.argv[2])
    for a in sys.argv[3:]:
        i, s = a.split(':'); i = int(i); s = bytes.fromhex(s)
        for _ in range(m):
            s = hashlib.sha256(s + salt + i.to_bytes(4, 'big')).digest()
        print(s.hex())
    """

func wordsHex(_ w: ArraySlice<UInt32>) -> String { w.map { String(format: "%08x", $0) }.joined() }

/// Run m = 1000 steps on chains 1, 2, 7 and one large index, split over uneven dispatches that
/// are committed back to back, and compare with Python hashlib. Returns true if all match.
func verify(_ v: Variant, tg: Int, quiet: Bool = false) -> Bool {
    let m = 1000
    let indices: [UInt32] = [1, 2, 7, 0x0001_0003]
    let salt = randomWords(4)
    let start = randomWords(indices.count * 8)
    let ch = Chains(v: v, n: indices.count, tg: tg, salt: salt, indices: indices, start: start)
    var done = 0
    var last: MTLCommandBuffer? = nil
    for k in [300, 300, 1, 399] {  // sums to 1000; exercises several dispatches and a 1-step one
        last = ch.commit(steps: k)
        done += k
    }
    precondition(done == m)
    last!.waitUntilCompleted()
    if let e = last!.error { fail("GPU error during verify: \(e)") }
    let gpu = ch.words()

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    var args = ["python3", "-c", pyRef, wordsHex(salt[...]), String(m)]
    for (j, i) in indices.enumerated() { args.append("\(i):" + wordsHex(start[(j * 8)..<(j * 8 + 8)])) }
    proc.arguments = args
    let pipe = Pipe()
    proc.standardOutput = pipe
    do { try proc.run() } catch { fail("could not run python3: \(error)") }
    let out = pipe.fileHandleForReading.readDataToEndOfFile()
    proc.waitUntilExit()
    guard proc.terminationStatus == 0 else { fail("python3 reference failed") }
    let ref = String(data: out, encoding: .utf8)!.split(separator: "\n").map(String.init)
    var ok = ref.count == indices.count
    for (j, i) in indices.enumerated() where ok {
        let g = wordsHex(gpu[(j * 8)..<(j * 8 + 8)])
        if g != ref[j] {
            ok = false
            print("MISMATCH variant \(v.name) chain \(i): gpu \(g) python \(ref[j])")
        }
    }
    if !quiet {
        print("verify \(v.name): \(ok ? "OK" : "FAILED") (m = \(m), chains \(indices.map(String.init).joined(separator: ",")), salt \(wordsHex(salt[...])), python hashlib)")
    }
    return ok
}

func requireVerified(_ vs: [Variant], tg: Int) {
    for v in Set(vs).sorted(by: { $0.name < $1.name }) {
        if !verify(v, tg: tg) { fail("correctness check failed for \(v.name): refusing to report") }
    }
}

// MARK: - Timing

struct Sample { let start: Double; let end: Double; let hashes: Double }

/// Choose steps per dispatch so one dispatch takes about `targetMs` of GPU time.
func calibrate(_ ch: Chains, targetMs: Double) -> Int {
    var k = 8
    while true {
        let cb = ch.commit(steps: k)
        cb.waitUntilCompleted()
        let t = cb.gpuEndTime - cb.gpuStartTime
        if t * 1e3 >= targetMs / 8 || k >= 1 << 28 {
            // Re-measure once at the estimate (the first dispatches may run at lower clocks).
            let est = max(1, min(Int(Double(k) * targetMs / 1e3 / max(t, 1e-7)), 1 << 30))
            let cb2 = ch.commit(steps: est)
            cb2.waitUntilCompleted()
            let t2 = cb2.gpuEndTime - cb2.gpuStartTime
            return max(1, min(Int(Double(est) * targetMs / 1e3 / max(t2, 1e-7)), 1 << 30))
        }
        k *= 8
    }
}

/// Run dispatches back to back (3 in flight) for `secs` seconds.
func timedRun(_ ch: Chains, k: Int, secs: Double) -> (wall: Double, samples: [Sample]) {
    let sem = DispatchSemaphore(value: 3)
    let lock = NSLock()
    var samples: [Sample] = []
    let hashesPer = Double(ch.n) * Double(k)
    let t0 = CACurrentMediaTime()
    var last: MTLCommandBuffer? = nil
    while CACurrentMediaTime() - t0 < secs {
        sem.wait()
        last = ch.commit(steps: k) { cb in
            lock.lock()
            samples.append(Sample(start: cb.gpuStartTime, end: cb.gpuEndTime, hashes: hashesPer))
            lock.unlock()
            sem.signal()
        }
    }
    last?.waitUntilCompleted()
    for _ in 0..<3 { sem.wait() }  // all completion handlers have run
    for _ in 0..<3 { sem.signal() }
    let wall = CACurrentMediaTime() - t0
    if let e = last?.error { fail("GPU error: \(e)") }
    return (wall, samples.sorted { $0.end < $1.end })
}

struct Result {
    let n: Int
    let k: Int
    let rate: Double  // chained hashes per second, wall clock
    let gpuRate: Double  // hashes / summed GPU time
    let msPerDispatch: Double
    let wall: Double
}

func measure(_ v: Variant, tg: Int, n: Int, secs: Double, targetMs: Double) -> Result {
    let salt = randomWords(4)
    let ch = Chains(
        v: v, n: n, tg: tg, salt: salt, indices: (0..<n).map { UInt32($0 + 1) },
        start: randomWords(n * 8))
    let k = calibrate(ch, targetMs: targetMs)
    _ = timedRun(ch, k: k, secs: min(0.3, secs))  // warm up
    let (wall, smp) = timedRun(ch, k: k, secs: secs)
    let total = smp.reduce(0) { $0 + $1.hashes }
    let busy = smp.reduce(0) { $0 + ($1.end - $1.start) }
    return Result(
        n: n, k: k, rate: total / wall, gpuRate: total / busy,
        msPerDispatch: busy / Double(smp.count) * 1e3, wall: wall)
}

func header() {
    print("# device: \(device.name)")
    print("# os: \(ProcessInfo.processInfo.operatingSystemVersionString)")
    print("# date: \(ISO8601DateFormatter().string(from: Date()))")
    print("# command: \(CommandLine.arguments.joined(separator: " "))")
}

func pad(_ x: String, _ w: Int, left: Bool = false) -> String {
    x.count >= w ? x : (left ? x + String(repeating: " ", count: w - x.count) : String(repeating: " ", count: w - x.count) + x)
}
func fmtRow(_ v: Variant, tg: Int, _ r: Result) -> String {
    let ns = 1e9 / (r.rate / Double(r.n))
    return pad(v.name, 8, left: true)
        + String(
            format: " %5d %8d %10d %10.2f %10.2f %11.1f %8.1f %7.2f", tg, r.n, r.k,
            r.rate / 1e6, r.gpuRate / 1e6, ns, r.msPerDispatch, r.wall)
}
let rowHeader = pad("variant", 8, left: true) + " " + [("tg", 5), ("chains", 8), ("K", 10), ("Mh/s", 10),
    ("Mh/s-gpu", 10), ("ns/step/ch", 11), ("ms/disp", 8), ("wall s", 7)].map { pad($0.0, $0.1) }.joined(separator: " ")

// MARK: - Main

var opts: [String: String] = [:]
var mode = "help"
do {
    var a = Array(CommandLine.arguments.dropFirst())
    if let f = a.first, !f.hasPrefix("--") { mode = f; a.removeFirst() }
    var j = 0
    while j < a.count {
        guard a[j].hasPrefix("--"), j + 1 < a.count else { fail("bad arguments") }
        opts[String(a[j].dropFirst(2))] = a[j + 1]
        j += 2
    }
}
func opt(_ k: String, _ d: String) -> String { opts[k] ?? d }
let variant = Variant.parse(opt("variant", "prex1"))
let tg = Int(opt("tg", "64"))!
let secs = Double(opt("secs", "2"))!
let targetMs = Double(opt("target-ms", "100"))!
let chainsList = opt("chains", "1,16,256,1024,4096,16384,65536,262144").split(separator: ",").map { Int($0)! }

switch mode {
case "verify":
    header()
    let vs = ["plainx1", "prex1", "premx1", "plainx2", "prex2", "premx2"].map(Variant.parse)
    var ok = true
    for v in vs { ok = verify(v, tg: tg) && ok }
    exit(ok ? 0 : 1)

case "source":
    print(shaderSource(variant))

case "sweep":
    // Throughput vs chains in flight, one variant.
    header()
    requireVerified([variant], tg: tg)
    print(rowHeader)
    for n in chainsList {
        let r = measure(variant, tg: tg, n: n, secs: secs, targetMs: targetMs)
        print(fmtRow(variant, tg: tg, r))
        fflush(stdout)
    }

case "tune":
    // Variants x threadgroup sizes at a fixed number of chains.
    header()
    let vs = opt("variants", "plainx1,prex1,premx1,plainx2,prex2,premx2").split(separator: ",").map { Variant.parse(String($0)) }
    let tgs = opt("tgs", "32,64,128,256,512,1024").split(separator: ",").map { Int($0)! }
    requireVerified(vs, tg: 64)
    for v in vs {
        print("# \(v.name): maxTotalThreadsPerThreadgroup \(pipeline(v).maxTotalThreadsPerThreadgroup), threadExecutionWidth \(pipeline(v).threadExecutionWidth)")
    }
    print(rowHeader)
    for n in chainsList {
        for v in vs {
            for t in tgs where t <= pipeline(v).maxTotalThreadsPerThreadgroup {
                let r = measure(v, tg: t, n: n, secs: secs, targetMs: targetMs)
                print(fmtRow(v, tg: t, r))
                fflush(stdout)
            }
        }
    }

case "sustain":
    // Continuous work at one configuration; prints rate per window and first/last 10 s.
    header()
    requireVerified([variant], tg: tg)
    let n = chainsList.last!
    let window = Double(opt("window", "5"))!
    let ch = Chains(
        v: variant, n: n, tg: tg, salt: randomWords(4), indices: (0..<n).map { UInt32($0 + 1) },
        start: randomWords(n * 8))
    let k = calibrate(ch, targetMs: targetMs)
    print("# sustain: \(variant.name), tg \(tg), \(n) chains, K = \(k) steps per dispatch, \(secs) s")
    fflush(stdout)
    let (wall, smp) = timedRun(ch, k: k, secs: secs)
    let t0 = smp.first!.start
    func rate(_ a: Double, _ b: Double) -> Double {
        // Dispatches that ended in (t0 + a, t0 + b], over the time from the previous end.
        var h = 0.0
        var lo = t0 + a, hi = lo
        var prevEnd = t0
        var first = true
        for s in smp {
            if s.end <= t0 + a { prevEnd = s.end; continue }
            if s.end > t0 + b { break }
            if first { lo = max(prevEnd, s.start); first = false }
            h += s.hashes
            hi = s.end
        }
        return h / (hi - lo)
    }
    let span = smp.last!.end - t0
    var a = 0.0
    while a + window <= span + 1e-9 {
        print(String(format: "t = %6.1f .. %6.1f s: %8.3f G hashes/s", a, a + window, rate(a, a + window) / 1e9))
        a += window
    }
    let total = smp.reduce(0) { $0 + $1.hashes }
    print(String(format: "first 10 s: %.3f G hashes/s", rate(0, 10) / 1e9))
    print(String(format: "last 10 s:  %.3f G hashes/s", rate(span - 10, span + 1) / 1e9))
    print(String(format: "whole run:  %.3f G hashes/s over %.1f s wall (%.3e hashes)", total / wall / 1e9, wall, total))

default:
    print(
        """
        usage: chainseal-metal <mode> [--option value ...]
          verify                 check all variants against Python hashlib (m = 1000)
          sweep                  throughput vs chains in flight  [--variant --tg --secs --chains --target-ms]
          tune                   variants x threadgroup sizes    [--variants --tgs --chains --secs]
          sustain                continuous run at one config    [--variant --tg --chains N --secs --window]
          source                 print the generated Metal source [--variant]
        variants: plain, pre, prem, each with x1 or x2 (pre = host-precomputed salt terms;
                  prem = pre + Maj computed with one fewer operation; xL = L chains per thread)
        defaults: --variant prex1 --tg 64 --secs 2 --target-ms 100
        """)
}

#import "LRQRScanScreen.h"
#import "LRDraw.h"
#import "LRToast.h"
#import <AVFoundation/AVFoundation.h>
#import <CoreMedia/CoreMedia.h>
#import <CoreVideo/CoreVideo.h>
#import <objc/message.h>
#include <dlfcn.h>
#include <zbar.h>
#include "amnezia_qr.h"

@interface LRQRScanScreen () <AVCaptureVideoDataOutputSampleBufferDelegate>
- (void)captureOutput:(AVCaptureOutput *)out didOutputMetadataObjects:(NSArray *)objects
       fromConnection:(AVCaptureConnection *)conn;
@end

/* the finder: four corner brackets over a darkened frame */
@interface LRFinderView : UIView
@end

@implementation LRFinderView
- (void)drawRect:(CGRect)rect {
    CGContextRef ctx = UIGraphicsGetCurrentContext();
    CGRect b = CGRectInset(self.bounds, 3, 3);
    LRSkin *s = SKIN;
    UIColor *c = [UIColor whiteColor];
    CGFloat len = b.size.width * 0.18f;
    CGContextSaveGState(ctx);
    if (!s->flat) CGContextSetShadowWithColor(ctx, CGSizeZero, 3, [UIColor colorWithWhite:0 alpha:0.6f].CGColor);
    [c setStroke];
    CGContextSetLineWidth(ctx, 4);
    CGContextSetLineCap(ctx, kCGLineCapRound);
    CGFloat x0 = b.origin.x, y0 = b.origin.y, x1 = CGRectGetMaxX(b), y1 = CGRectGetMaxY(b);
    CGPoint corners[4][3] = {
        { {x0, y0 + len}, {x0, y0}, {x0 + len, y0} }, { {x1 - len, y0}, {x1, y0}, {x1, y0 + len} },
        { {x1, y1 - len}, {x1, y1}, {x1 - len, y1} }, { {x0 + len, y1}, {x0, y1}, {x0, y1 - len} } };
    for (int i = 0; i < 4; ++i) {
        CGContextMoveToPoint(ctx, corners[i][0].x, corners[i][0].y);
        CGContextAddLineToPoint(ctx, corners[i][1].x, corners[i][1].y);
        CGContextAddLineToPoint(ctx, corners[i][2].x, corners[i][2].y);
    }
    CGContextStrokePath(ctx);
    CGContextRestoreGState(ctx);
}
@end

static NSString *LRQRMetadataType(void) {
    NSString * const *symbol = (NSString * const *)dlsym(RTLD_DEFAULT, "AVMetadataObjectTypeQRCode");
    return symbol && *symbol ? *symbol : @"org.iso.QRCode";
}

NSString *LRDecodeQRImage(UIImage *photo) {
    CGImageRef cg = photo.CGImage;
    if (!cg) return nil;
    size_t w = CGImageGetWidth(cg), h = CGImageGetHeight(cg);
    /* big photos are scaled down: zbar wants a few pixels per module, not 12 */
    CGFloat scale = MIN(1.0f, 1600.0f / MAX(w, h));
    w = (size_t)(w * scale);
    h = (size_t)(h * scale);
    if (!w || !h) return nil;
    uint8_t *gray = calloc(w * h, 1);
    CGColorSpaceRef space = CGColorSpaceCreateDeviceGray();
    CGContextRef bm = CGBitmapContextCreate(gray, w, h, 8, w, space, kCGImageAlphaNone);
    CGColorSpaceRelease(space);
    if (!bm) { free(gray); return nil; }
    CGContextDrawImage(bm, CGRectMake(0, 0, w, h), cg);
    CGContextRelease(bm);
    zbar_image_scanner_t *scanner = zbar_image_scanner_create();
    zbar_image_t *image = zbar_image_create();
    zbar_image_scanner_set_config(scanner, ZBAR_QRCODE, ZBAR_CFG_ENABLE, 1);
    zbar_image_set_format(image, zbar_fourcc('Y', '8', '0', '0'));
    zbar_image_set_size(image, (unsigned)w, (unsigned)h);
    zbar_image_set_data(image, gray, (unsigned long)(w * h), NULL);
    NSString *text = nil;
    if (zbar_scan_image(scanner, image) > 0) {
        for (const zbar_symbol_t *sym = zbar_image_first_symbol(image); sym; sym = zbar_symbol_next(sym)) {
            if (zbar_symbol_get_type(sym) != ZBAR_QRCODE) continue;
            text = [[[NSString alloc] initWithBytes:zbar_symbol_get_data(sym)
                                             length:zbar_symbol_get_data_length(sym)
                                           encoding:NSUTF8StringEncoding] autorelease];
            if (text) break;
        }
    }
    zbar_image_set_data(image, NULL, 0, NULL);
    zbar_image_destroy(image);
    zbar_image_scanner_destroy(scanner);
    free(gray);
    return text;
}

@implementation LRQRScanScreen
@synthesize completion = _completion;

- (id)init {
    if ((self = [super init])) {
        self.title = L(@"Scan QR Code");
        _backgroundStyle = LRBackgroundDenim;
    }
    return self;
}

- (void)teardownCapture {
    if (_videoOutput) [(AVCaptureVideoDataOutput *)_videoOutput setSampleBufferDelegate:nil queue:NULL];
    if (_metadataOutput) {
        SEL clear = NSSelectorFromString(@"setMetadataObjectsDelegate:queue:");
        if ([_metadataOutput respondsToSelector:clear])
            ((void (*)(id, SEL, id, dispatch_queue_t))objc_msgSend)(_metadataOutput, clear, nil, NULL);
    }
    if (_session) [(AVCaptureSession *)_session stopRunning];
    if (_queue) dispatch_sync(_queue, ^{});
}

- (void)dealloc {
    [self teardownCapture];
    if (_image) zbar_image_destroy(_image);
    if (_scanner) zbar_image_scanner_destroy(_scanner);
    if (_frames) amz_qr_free((amz_qr_t *)_frames);
    free(_frames);
    free(_pixels);
    [_session release];
    [_videoOutput release];
    [_metadataOutput release];
    [_previewLayer release];
    [_device release];
    if (_queue) dispatch_release(_queue);
    [_finder release];
    [_hint release];
    [_torch release];
    [_photos release];
    [_popover release];
    [_completion release];
    [super dealloc];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    __block LRQRScanScreen *me = self;
    self.manualLeftButton = YES;
    [self.header setLeftTitle:L(@"Cancel") style:LRButtonMetal action:^(LRButton *b) { [me finish:nil]; }];
    self.contentView.backgroundColor = [UIColor blackColor];
    _finder = [[LRFinderView alloc] initWithFrame:CGRectZero];
    _finder.backgroundColor = [UIColor clearColor];
    _finder.contentMode = UIViewContentModeRedraw;
    [self.contentView addSubview:_finder];
    _hint = [[UILabel alloc] init];
    _hint.backgroundColor = [UIColor colorWithWhite:0 alpha:0.55f];
    _hint.textColor = [UIColor whiteColor];
    _hint.font = [LRSkin bodyFont:13];
    _hint.numberOfLines = 3;
    _hint.textAlignment = NSTextAlignmentCenter;
    _hint.text = L(@"Point the camera at a QR code with a server link, a subscription or a WireGuard / AmneziaWG profile");
    _hint.layer.cornerRadius = 8;
    [self.contentView addSubview:_hint];
    _torch = [[LRButton buttonWithStyle:LRButtonDark title:L(@"Light") action:^(LRButton *b) {
        [me toggleTorch];
    }] retain];
    _photos = [[LRButton buttonWithStyle:LRButtonDark title:L(@"From Photos") action:^(LRButton *b) {
        [me pickPhoto:b];
    }] retain];
    for (LRButton *b in [NSArray arrayWithObjects:_torch, _photos, nil]) {
        b.frame = CGRectMake(0, 0, 120, 40);
        b.titleLabel.font = [LRSkin boldFont:14];
        [self.contentView addSubview:b];
    }
    _torch.hidden = YES;
    [self setupCapture];
}

- (void)layoutContent {
    CGRect b = self.contentView.bounds;
    ((CALayer *)_previewLayer).frame = b;
    CGFloat box = MIN(MIN(b.size.width, b.size.height) * 0.68f, 320.0f);
    _finder.frame = CGRectMake(roundf((b.size.width - box) / 2), roundf((b.size.height - box) / 2 - 30), box, box);
    [_finder setNeedsDisplay];
    CGFloat bw = MIN(140.0f, (b.size.width - 60) / 2);
    _torch.frame = CGRectMake(roundf(b.size.width / 2 - bw - 10), b.size.height - 56, bw, 40);
    _photos.frame = CGRectMake(roundf(b.size.width / 2 + 10), b.size.height - 56, bw, 40);
    if (_torch.hidden) _photos.frame = CGRectMake(roundf((b.size.width - bw) / 2), b.size.height - 56, bw, 40);
    _hint.frame = CGRectMake(20, CGRectGetMaxY(_finder.frame) + 14, b.size.width - 40, 54);
    [self orientPreview];
}

- (void)orientPreview {
    id preview = _previewLayer;
    SEL connectionSel = NSSelectorFromString(@"connection");
    if (!preview || ![preview respondsToSelector:connectionSel]) return;
    id connection = ((id (*)(id, SEL))objc_msgSend)(preview, connectionSel);
    SEL supports = NSSelectorFromString(@"isVideoOrientationSupported");
    SEL setter = NSSelectorFromString(@"setVideoOrientation:");
    if ([connection respondsToSelector:supports] && [connection respondsToSelector:setter] &&
        ((BOOL (*)(id, SEL))objc_msgSend)(connection, supports))
        ((void (*)(id, SEL, NSInteger))objc_msgSend)(connection, setter,
            (NSInteger)[UIApplication sharedApplication].statusBarOrientation);
}

- (void)finish:(NSString *)text {
    if (_done && text) return;
    _done = YES;
    [self teardownCapture];
    [self setTorchOn:NO];
    void (^completion)(NSString *) = [[_completion retain] autorelease];
    [_completion release];
    _completion = nil;
    LRDismissModal(self.navigationController ? (UIViewController *)self.navigationController : self, YES);
    if (completion) completion(text);
}

/* the amnezia client shows a profile as a series of codes; each one is kept
   until the series is whole, and the joined text goes on like any other */
- (NSString *)joinAmneziaFrame:(NSString *)text {
    if (!_frames) {
        _frames = calloc(1, sizeof(amz_qr_t));
        if (!_frames) return text;
        amz_qr_init((amz_qr_t *)_frames);
    }
    amz_qr_t *q = (amz_qr_t *)_frames;
    NSData *bytes = [text dataUsingEncoding:NSUTF8StringEncoding];
    amz_qr_status_t st = amz_qr_add(q, (const char *)[bytes bytes], [bytes length]);
    if (st == AMZ_QR_PART || st == AMZ_QR_REPEAT) {
        _hint.text = [NSString stringWithFormat:L(@"Amnezia code %u of %u: keep the camera on the next code"),
                      (unsigned)q->have, (unsigned)q->count];
        return nil;
    }
    if (st == AMZ_QR_ERR_SPACE) {
        amz_qr_free(q);
        _hint.text = L(@"The Amnezia profile is too large");
        return nil;
    }
    if (st != AMZ_QR_DONE) return text;
    size_t cap = AMZ_QR_MAX_BYTES * 2, len = 0;
    char *joined = malloc(cap);
    NSString *whole = nil;
    if (joined && amz_qr_result(q, joined, cap, &len) == 0)
        whole = [[[NSString alloc] initWithBytes:joined length:len
                                        encoding:NSUTF8StringEncoding] autorelease];
    free(joined);
    amz_qr_free(q);
    if (!whole) _hint.text = L(@"The Amnezia codes could not be joined");
    return whole;
}

- (void)hit:(NSString *)text {
    if (_done) return;
    _done = YES;
    NSString *copy = [text copy];
    dispatch_async(dispatch_get_main_queue(), ^{
        _done = NO;
        NSString *whole = [self joinAmneziaFrame:copy];
        if (whole) [self finish:whole];
        [copy release];
    });
}

#pragma mark camera

- (void)showProblem:(NSString *)text {
    _hint.text = text;
}

- (void)setupCapture {
    if (_setup) return;
    Class devClass = NSClassFromString(@"AVCaptureDevice");
    AVCaptureDevice *cam = nil;
    if (devClass) {
        for (AVCaptureDevice *d in [devClass devicesWithMediaType:AVMediaTypeVideo])
            if ([d position] == AVCaptureDevicePositionBack) cam = d;
        if (!cam) cam = [devClass defaultDeviceWithMediaType:AVMediaTypeVideo];
    }
    if (!cam) {
        [self showProblem:L(@"This device has no camera. Choose a picture of the QR code from Photos.")];
        return;
    }
    AVCaptureDeviceInput *input = [AVCaptureDeviceInput deviceInputWithDevice:cam error:NULL];
    if (!input) {
        [self showProblem:L(@"The camera is unavailable. Allow access in Settings > Privacy > Camera.")];
        return;
    }
    AVCaptureSession *session = [[AVCaptureSession alloc] init];
    [session beginConfiguration];
    if (![session canAddInput:input]) {
        [session commitConfiguration];
        [session release];
        [self showProblem:L(@"The camera is unavailable")];
        return;
    }
    [session addInput:input];
    if ([session canSetSessionPreset:AVCaptureSessionPreset1280x720])
        session.sessionPreset = AVCaptureSessionPreset1280x720;
    else if ([session canSetSessionPreset:AVCaptureSessionPreset640x480])
        session.sessionPreset = AVCaptureSessionPreset640x480;
    [session commitConfiguration];
    [self addMetadataOutput:session];
    [self addFrameOutput:session];
    if ([cam lockForConfiguration:NULL]) {
        if ([cam isFocusModeSupported:AVCaptureFocusModeContinuousAutoFocus])
            cam.focusMode = AVCaptureFocusModeContinuousAutoFocus;
        if ([cam isExposureModeSupported:AVCaptureExposureModeContinuousAutoExposure])
            cam.exposureMode = AVCaptureExposureModeContinuousAutoExposure;
        [cam unlockForConfiguration];
    }
    AVCaptureVideoPreviewLayer *preview = [[AVCaptureVideoPreviewLayer alloc] initWithSession:session];
    preview.videoGravity = AVLayerVideoGravityResizeAspectFill;
    [self.contentView.layer insertSublayer:preview atIndex:0];
    _previewLayer = preview;
    _session = session;
    _device = [cam retain];
    _setup = YES;
    _torch.hidden = ![cam hasTorch];
    [self layoutContent];
    [session startRunning];
}

- (void)addMetadataOutput:(AVCaptureSession *)session {
    Class cls = NSClassFromString(@"AVCaptureMetadataOutput");
    if (!cls) return;
    id out = [[cls alloc] init];
    SEL types = NSSelectorFromString(@"availableMetadataObjectTypes");
    SEL setTypes = NSSelectorFromString(@"setMetadataObjectTypes:");
    SEL setDelegate = NSSelectorFromString(@"setMetadataObjectsDelegate:queue:");
    if (![session canAddOutput:out] || ![out respondsToSelector:setDelegate]) {
        [out release];
        return;
    }
    [session addOutput:out];
    NSArray *available = ((id (*)(id, SEL))objc_msgSend)(out, types);
    if (![available containsObject:LRQRMetadataType()]) {
        [session removeOutput:out];
        [out release];
        return;
    }
    ((void (*)(id, SEL, id))objc_msgSend)(out, setTypes, [NSArray arrayWithObject:LRQRMetadataType()]);
    ((void (*)(id, SEL, id, dispatch_queue_t))objc_msgSend)(out, setDelegate, self, dispatch_get_main_queue());
    _metadataOutput = out;
}

- (void)addFrameOutput:(AVCaptureSession *)session {
    _scanner = zbar_image_scanner_create();
    _image = zbar_image_create();
    if (!_scanner || !_image) return;
    zbar_image_scanner_set_config(_scanner, ZBAR_QRCODE, ZBAR_CFG_ENABLE, 1);
    zbar_image_scanner_enable_cache(_scanner, 0);
    AVCaptureVideoDataOutput *out = [[AVCaptureVideoDataOutput alloc] init];
    out.alwaysDiscardsLateVideoFrames = YES;
    if (![session canAddOutput:out]) {
        [out release];
        return;
    }
    [session addOutput:out];
    NSArray *formats = [out availableVideoCVPixelFormatTypes];
    unsigned wanted[3] = { kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
                           kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, kCVPixelFormatType_32BGRA };
    for (int i = 0; i < 3; ++i) {
        if ([formats containsObject:[NSNumber numberWithUnsignedInt:wanted[i]]]) {
            out.videoSettings = [NSDictionary dictionaryWithObject:[NSNumber numberWithUnsignedInt:wanted[i]]
                                                            forKey:(NSString *)kCVPixelBufferPixelFormatTypeKey];
            break;
        }
    }
    _queue = dispatch_queue_create("legacyray.qr", NULL);
    [out setSampleBufferDelegate:self queue:_queue];
    _videoOutput = out;
}

- (void)captureOutput:(AVCaptureOutput *)out didOutputSampleBuffer:(CMSampleBufferRef)sb
       fromConnection:(AVCaptureConnection *)conn {
    if (_done || !_scanner || !_image) return;
    CVImageBufferRef img = CMSampleBufferGetImageBuffer(sb);
    if (!img) return;
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    CVPixelBufferLockBaseAddress(img, kCVPixelBufferLock_ReadOnly);
    OSType fmt = CVPixelBufferGetPixelFormatType(img);
    BOOL planar = fmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange ||
                  fmt == kCVPixelFormatType_420YpCbCr8BiPlanarFullRange;
    size_t w = planar ? CVPixelBufferGetWidthOfPlane(img, 0) : CVPixelBufferGetWidth(img);
    size_t h = planar ? CVPixelBufferGetHeightOfPlane(img, 0) : CVPixelBufferGetHeight(img);
    size_t count = w * h;
    if (count && count > _capacity) {
        zbar_image_set_data(_image, NULL, 0, NULL);
        uint8_t *p = realloc(_pixels, count);
        if (p) { _pixels = p; _capacity = count; }
    }
    if (count && count <= _capacity) {
        if (planar) {
            uint8_t *base = CVPixelBufferGetBaseAddressOfPlane(img, 0);
            size_t stride = CVPixelBufferGetBytesPerRowOfPlane(img, 0);
            for (size_t y = 0; base && y < h; ++y) memcpy(_pixels + y * w, base + y * stride, w);
        } else {
            uint8_t *base = CVPixelBufferGetBaseAddress(img);
            size_t stride = CVPixelBufferGetBytesPerRow(img);
            for (size_t y = 0; base && y < h; ++y) {
                uint8_t *row = base + y * stride, *dst = _pixels + y * w;
                for (size_t x = 0; x < w; ++x)
                    dst[x] = (uint8_t)((row[x * 4 + 2] * 77 + row[x * 4 + 1] * 150 + row[x * 4] * 29) >> 8);
            }
        }
        zbar_image_set_format(_image, zbar_fourcc('Y', '8', '0', '0'));
        zbar_image_set_size(_image, (unsigned)w, (unsigned)h);
        zbar_image_set_data(_image, _pixels, (unsigned long)count, NULL);
        zbar_scan_image(_scanner, _image);
        for (const zbar_symbol_t *sym = zbar_image_first_symbol(_image); sym; sym = zbar_symbol_next(sym)) {
            if (zbar_symbol_get_type(sym) != ZBAR_QRCODE) continue;
            NSString *text = [[[NSString alloc] initWithBytes:zbar_symbol_get_data(sym)
                                                       length:zbar_symbol_get_data_length(sym)
                                                     encoding:NSUTF8StringEncoding] autorelease];
            if ([text length]) { [self hit:text]; break; }
        }
    }
    CVPixelBufferUnlockBaseAddress(img, kCVPixelBufferLock_ReadOnly);
    [pool release];
}

- (void)captureOutput:(AVCaptureOutput *)out didOutputMetadataObjects:(NSArray *)objects
       fromConnection:(AVCaptureConnection *)conn {
    SEL stringSel = NSSelectorFromString(@"stringValue");
    for (id object in objects) {
        if (![object respondsToSelector:stringSel]) continue;
        NSString *text = ((id (*)(id, SEL))objc_msgSend)(object, stringSel);
        if ([text length]) { [self hit:text]; return; }
    }
}

#pragma mark torch

- (void)setTorchOn:(BOOL)on {
    AVCaptureDevice *cam = _device;
    if (!cam || ![cam hasTorch] || ![cam lockForConfiguration:NULL]) return;
    if ([cam isTorchModeSupported:on ? AVCaptureTorchModeOn : AVCaptureTorchModeOff])
        cam.torchMode = on ? AVCaptureTorchModeOn : AVCaptureTorchModeOff;
    [cam unlockForConfiguration];
}

- (void)toggleTorch {
    AVCaptureDevice *cam = _device;
    BOOL on = cam && cam.torchMode != AVCaptureTorchModeOn;
    [self setTorchOn:on];
    _torch.style = on ? LRButtonGreen : LRButtonDark;
}

#pragma mark photos

- (void)pickPhoto:(UIView *)anchor {
    if (![UIImagePickerController isSourceTypeAvailable:UIImagePickerControllerSourceTypePhotoLibrary]) return;
    UIImagePickerController *picker = [[[UIImagePickerController alloc] init] autorelease];
    picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    picker.delegate = self;
    if (LRIsPad()) {
        Class popoverClass = NSClassFromString(@"UIPopoverController");
        [_popover release];
        _popover = [[popoverClass alloc] initWithContentViewController:picker];
        [_popover setDelegate:self];
        [_popover presentPopoverFromRect:anchor.bounds inView:anchor
                permittedArrowDirections:UIPopoverArrowDirectionAny animated:YES];
    } else {
        LRPresentModal(self.navigationController ? (UIViewController *)self.navigationController : self,
                       picker, YES);
    }
}

- (void)closePicker:(UIImagePickerController *)picker {
    if (_popover) {
        [_popover dismissPopoverAnimated:YES];
        [_popover release];
        _popover = nil;
    } else {
        LRDismissModal(picker, YES);
    }
}

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary *)info {
    UIImage *image = [info objectForKey:UIImagePickerControllerOriginalImage];
    [self closePicker:picker];
    NSString *text = LRDecodeQRImage(image);
    if (text) [self performSelector:@selector(finish:) withObject:text afterDelay:0.5];
    else [LRToast showError:L(@"No QR code found in this picture")];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [self closePicker:picker];
}

- (void)popoverControllerDidDismissPopover:(UIPopoverController *)popover {
    [_popover release];
    _popover = nil;
}
@end

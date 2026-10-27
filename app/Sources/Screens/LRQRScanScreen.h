/* the QR camera: zbar on every system, the ios 7 system detector when it is
   there, a torch key, and decoding from a saved photo for devices without a
   camera (the first ipad) */
#import "LRScreen.h"
#include <dispatch/dispatch.h>

typedef struct zbar_image_s zbar_image_t;
typedef struct zbar_image_scanner_s zbar_image_scanner_t;

@interface LRQRScanScreen : LRScreen <UIImagePickerControllerDelegate, UINavigationControllerDelegate,
                                      UIPopoverControllerDelegate> {
    id _session;
    id _videoOutput;
    id _metadataOutput;
    id _previewLayer;
    id _device;
    dispatch_queue_t _queue;
    zbar_image_scanner_t *_scanner;
    zbar_image_t *_image;
    uint8_t *_pixels;
    size_t _capacity;
    BOOL _done;
    BOOL _setup;
    UIView *_finder;
    UILabel *_hint;
    LRButton *_torch;
    LRButton *_photos;
    id _popover;
    void *_frames; /* amz_qr_t: the amnezia series collected so far */
    void (^_completion)(NSString *text);
}
/* called once with the decoded text, or nil when the user cancels */
@property (nonatomic, copy) void (^completion)(NSString *text);
@end

/* decode the first QR code in a still image, nil when there is none */
NSString *LRDecodeQRImage(UIImage *image);

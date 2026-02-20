import cv2
import numpy as np
try:
    from pyzbar.pyzbar import decode
    PYZBAR_AVAILABLE = True
except Exception as e:
    print(f"Warning: pyzbar libraries (DLLs) not found. Barcode scanning will be disabled. Error: {e}")
    PYZBAR_AVAILABLE = False
import qrcode
import base64
import io
from PIL import Image

class BarcodeScanner:
    """Module for scanning and generating barcodes and QR codes"""
    
    @staticmethod
    def decode_from_base64(base64_string):
        """Decode barcode from a base64 encoded image string"""
        try:
            if ',' in base64_string:
                base64_string = base64_string.split(',')[1]
            
            decoded_data = base64.b64decode(base64_string)
            np_arr = np.frombuffer(decoded_data, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            
            if img is None:
                return {"success": False, "error": "Could not decode image"}
            
            results = []
            
            # 1. Try PyZBar if available (supports barcodes + QR)
            if PYZBAR_AVAILABLE:
                try:
                    barcodes = decode(img)
                    for barcode in barcodes:
                        barcode_data = barcode.data.decode("utf-8")
                        barcode_type = barcode.type
                        results.append({
                            "data": barcode_data,
                            "type": barcode_type,
                            "rect": list(barcode.rect)
                        })
                except Exception as e:
                    print(f"PyZBar error during scan: {e}")

            # 2. Fallback to OpenCV QRCodeDetector (QR only, but no external DLLs needed)
            if not results:
                try:
                    detector = cv2.QRCodeDetector()
                    
                    # Try original image
                    data, vertices, _ = detector.detectAndDecode(img)
                    
                    # If failed, try grayscale
                    if not data:
                        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                        data, vertices, _ = detector.detectAndDecode(gray)
                        
                    # If still failed, try thresholding
                    if not data:
                        _, thresh = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
                        data, vertices, _ = detector.detectAndDecode(thresh)

                    if data:
                        results.append({
                            "data": data,
                            "type": "QRCODE (OpenCV)",
                            "rect": [] 
                        })
                except Exception as e:
                    print(f"OpenCV QR error: {e}")
                    
            if not results:
                msg = "No barcode or QR code detected."
                if not PYZBAR_AVAILABLE:
                    msg += " (Note: ZBar DLLs missing, only QR codes can be scanned using OpenCV fallback)"
                return {"success": False, "error": msg}
                
            return {"success": True, "results": results}
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def generate_qr_base64(data):
        """Generate a QR code image as a base64 string"""
        try:
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode()
            
            return f"data:image/png;base64,{img_str}"
        except Exception as e:
            print(f"Error generating QR code: {e}")
            return None

# Global instance
barcode_scanner = BarcodeScanner()

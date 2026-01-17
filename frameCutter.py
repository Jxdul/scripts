#!/usr/bin/env python3
"""
Script to split vertical images (1200x1800) in half vertically
and save the left halves to ~/Downloads folder.
"""

import os
import sys
from pathlib import Path
from PIL import Image


def split_image_vertically(image_path, output_dir):
    """
    Split an image vertically in half and save the left part.
    
    Args:
        image_path: Path to the input image
        output_dir: Directory to save the left half
    """
    try:
        # Open the image
        img = Image.open(image_path)
        width, height = img.size
        
        # Calculate the midpoint (splitting vertically means splitting width)
        midpoint = width // 2
        
        # Extract left half (from x=0 to x=midpoint)
        left_half = img.crop((0, 0, midpoint, height))
        
        # Generate output filename
        input_name = Path(image_path).stem
        input_ext = Path(image_path).suffix
        output_path = Path(output_dir) / f"{input_name}_left{input_ext}"
        
        # Save the left half
        left_half.save(output_path)
        print(f"Saved left half: {output_path}")
        
        return True
        
    except Exception as e:
        print(f"Error processing {image_path}: {e}", file=sys.stderr)
        return False


def main():
    # Set output directory to ~/Downloads
    output_dir = Path.home() / "Downloads"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if images were provided as arguments
    if len(sys.argv) < 2:
        print("Usage: python frameCutter <image1> <image2> ...", file=sys.stderr)
        print("Or: python frameCutter *.jpg", file=sys.stderr)
        sys.exit(1)
    
    # Process each image file
    success_count = 0
    for image_path in sys.argv[1:]:
        if os.path.isfile(image_path):
            if split_image_vertically(image_path, output_dir):
                success_count += 1
        else:
            print(f"Warning: {image_path} is not a valid file", file=sys.stderr)
    
    print(f"\nProcessed {success_count} image(s) successfully.")


if __name__ == "__main__":
    main()

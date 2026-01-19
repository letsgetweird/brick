import os
import asyncio
import time
from pathlib import Path

class ZeekMonitor:
    """Monitors Zeek processing by tracking log file growth"""
    
    def __init__(self, progress_callback=None):
        """
        Initialize the Zeek monitor
        
        Args:
            progress_callback: Function to call with (stage, message) updates
                              where stage ranges from 0-4
        """
        self.on_progress = progress_callback
        self.logs_directory = '/data/zeek_logs'  # Matches compose.yaml working_dir
        self.pcap_file = '/uploads/input.pcap'
        
    def report_progress(self, stage: int, message: str):
        """
        Report progress to the callback
        
        Args:
            stage: Progress stage (0=hidden, 1=25%, 2=50%, 3=75%, 4=100%)
            message: Human-readable status message
        """
        if self.on_progress:
            self.on_progress(stage, message)
    
    def get_pcap_size(self):
        """Get the size of the input PCAP file in bytes"""
        try:
            return os.path.getsize(self.pcap_file)
        except:
            return 0
    
    def get_total_log_size(self):
        """Calculate total size of all Zeek log files"""
        total_size = 0
        try:
            for filename in os.listdir(self.logs_directory):
                if filename.endswith('.log'):
                    file_path = os.path.join(self.logs_directory, filename)
                    try:
                        total_size += os.path.getsize(file_path)
                    except:
                        pass
        except:
            pass
        return total_size
    
    def calculate_progress(self, log_size, pcap_size):
        """
        Estimate processing progress based on log file growth
        
        Zeek typically generates logs that are 10-30% of the original PCAP size.
        We use a conservative estimate of 15% to calculate progress.
        
        Args:
            log_size: Current total size of all log files
            pcap_size: Size of the input PCAP file
            
        Returns:
            Progress percentage (capped at 95% until completion is confirmed)
        """
        if pcap_size == 0:
            return 0
        
        # Conservative estimate: logs will be ~15% of PCAP size when done
        expected_log_size = pcap_size * 0.15
        
        if expected_log_size == 0:
            return 0
        
        # Calculate percentage complete
        progress_percentage = (log_size / expected_log_size) * 100
        
        # Cap at 95% until we confirm files have stopped growing
        return min(progress_percentage, 95)
    
    def count_detected_protocols(self):
        """Count how many ICS protocols were detected"""
        ics_protocol_logs = ['modbus.log', 'enip.log', 's7comm.log', 'dnp3.log', 'bacnet.log']
        detected_count = 0
        
        for log_name in ics_protocol_logs:
            log_path = os.path.join(self.logs_directory, log_name)
            try:
                # Check if log exists and has meaningful content (>100 bytes)
                if os.path.exists(log_path) and os.path.getsize(log_path) > 100:
                    detected_count += 1
            except:
                pass
                
        return detected_count
    
    async def watch_processing(self, timeout_seconds: int = 300):
        """
        Monitor Zeek processing by watching log file growth
        
        Args:
            timeout_seconds: Maximum time to wait for processing (default: 5 minutes)
            
        Returns:
            True if processing completed successfully, False if timeout or error
        """
        pcap_size = self.get_pcap_size()
        
        if pcap_size == 0:
            self.report_progress(0, "No PCAP file found")
            return False
        
        # Stage 1: PCAP is uploaded, waiting for Zeek to start
        self.report_progress(1, "PCAP uploaded, waiting for Zeek to start...")
        
        start_time = time.time()
        connection_log = os.path.join(self.logs_directory, 'conn.log')
        
        # Wait up to 60 seconds for Zeek to create the connection log
        wait_start = time.time()
        while time.time() - wait_start < 60:
            if os.path.exists(connection_log) and os.path.getsize(connection_log) > 100:
                break
            await asyncio.sleep(2)
        else:
            # Timeout waiting for Zeek to start
            self.report_progress(0, "Zeek not processing - check Zeek container")
            return False
        
        # Stage 2: Zeek has started processing
        self.report_progress(2, "Zeek processing... 0%")
        
        previous_log_size = 0
        unchanged_count = 0
        current_stage = 2
        
        # Monitor log growth until completion or timeout
        while time.time() - start_time < timeout_seconds:
            current_log_size = self.get_total_log_size()
            
            # Calculate progress percentage
            progress_pct = self.calculate_progress(current_log_size, pcap_size)
            
            # Update stage based on progress
            if progress_pct >= 75 and current_stage < 3:
                # Stage 3: Nearly complete
                self.report_progress(3, f"Zeek finalizing... {int(progress_pct)}%")
                current_stage = 3
            elif progress_pct >= 50 and current_stage < 3:
                # Still in stage 2, but update percentage
                self.report_progress(2, f"Zeek processing... {int(progress_pct)}%")
            
            # Check if files have stopped growing (processing complete)
            if current_log_size == previous_log_size:
                unchanged_count += 1
                if unchanged_count >= 3:  # Stable for 6 seconds (3 checks × 2 seconds)
                    # Processing is complete!
                    break
            else:
                unchanged_count = 0
                previous_log_size = current_log_size
            
            await asyncio.sleep(2)
        
        # Check if we hit the timeout
        if time.time() - start_time >= timeout_seconds:
            self.report_progress(0, "Processing timeout - check logs")
            return False
        
        # Stage 4: Complete!
        self.report_progress(4, "Complete")
        
        return True


async def track_zeek_progress(progress_callback):
    """
    Track Zeek progress by monitoring log file growth
    
    This is a convenience function that creates a ZeekMonitor and starts monitoring.
    
    Args:
        progress_callback: Function to call with (stage, message) updates
    
    Returns:
        True if processing completed successfully, False otherwise
    """
    monitor = ZeekMonitor(progress_callback)
    return await monitor.watch_processing()

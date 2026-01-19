import os
import asyncio
import time
from pathlib import Path

class RealZeekProgress:
    """Track Zeek progress by monitoring log file growth"""
    
    def __init__(self, progress_callback=None):
        """
        Args:
            progress_callback: Function(stage, message) where stage is 0-4
        """
        self.progress_callback = progress_callback
        self.zeek_logs_dir = '/data/zeek_logs'  # Match compose.yaml working_dir
        self.pcap_path = '/uploads/input.pcap'
        
    def update_progress(self, stage: int, message: str):
        """Update progress (0=hidden, 1=25%, 2=50%, 3=75%, 4=100%)"""
        if self.progress_callback:
            self.progress_callback(stage, message)
    
    def get_pcap_size(self):
        """Get PCAP file size in bytes"""
        try:
            return os.path.getsize(self.pcap_path)
        except:
            return 0
    
    def get_total_log_size(self):
        """Get total size of all Zeek log files"""
        total = 0
        try:
            for file in os.listdir(self.zeek_logs_dir):
                if file.endswith('.log'):
                    filepath = os.path.join(self.zeek_logs_dir, file)
                    try:
                        total += os.path.getsize(filepath)
                    except:
                        pass
        except:
            pass
        return total
    
    def estimate_progress(self, log_size, pcap_size):
        """
        Estimate progress based on log file size vs PCAP size
        
        Typical ratio: Logs are 10-30% of PCAP size
        We'll be conservative and say logs = 15% of PCAP when complete
        """
        if pcap_size == 0:
            return 0
        
        # Assume logs will be ~15% of PCAP size when complete
        expected_final_log_size = pcap_size * 0.15
        
        if expected_final_log_size == 0:
            return 0
        
        # Calculate percentage
        progress = (log_size / expected_final_log_size) * 100
        
        # Cap at 95% until we're sure it's done (files stopped growing)
        return min(progress, 95)
    
    def count_protocols(self):
        """Count ICS protocols detected"""
        ics_logs = ['modbus.log', 'enip.log', 's7comm.log', 'dnp3.log', 'bacnet.log']
        count = 0
        for log in ics_logs:
            log_path = os.path.join(self.zeek_logs_dir, log)
            try:
                if os.path.exists(log_path) and os.path.getsize(log_path) > 100:
                    count += 1
            except:
                pass
        return count
    
    async def monitor_zeek(self, timeout: int = 300):
        """
        Monitor Zeek processing by watching log file growth
        
        Returns:
            True if successful, False if timeout/error
        """
        pcap_size = self.get_pcap_size()
        
        if pcap_size == 0:
            self.update_progress(0, "No PCAP file found")
            return False
        
        # Stage 1: 25% - PCAP uploaded, waiting for Zeek to start
        self.update_progress(1, "PCAP uploaded, waiting for Zeek to start...")
        
        start_time = time.time()
        conn_log = os.path.join(self.zeek_logs_dir, 'conn.log')
        
        # Wait for conn.log to appear (max 60 seconds)
        wait_start = time.time()
        while time.time() - wait_start < 60:
            if os.path.exists(conn_log) and os.path.getsize(conn_log) > 100:
                break
            await asyncio.sleep(2)
        else:
            # Zeek hasn't started after 60 seconds
            self.update_progress(0, "Zeek not processing - check Zeek container")
            return False
        
        # Stage 2: 50% - Zeek started, monitoring progress
        self.update_progress(2, "Zeek processing... 0%")
        
        last_log_size = 0
        stable_count = 0
        last_progress_stage = 2
        
        # Monitor log growth
        while time.time() - start_time < timeout:
            current_log_size = self.get_total_log_size()
            
            # Calculate progress
            progress_pct = self.estimate_progress(current_log_size, pcap_size)
            
            # Update stage based on progress
            if progress_pct >= 75 and last_progress_stage < 3:
                # Stage 3: 75%
                self.update_progress(3, f"Zeek finalizing... {int(progress_pct)}%")
                last_progress_stage = 3
            elif progress_pct >= 50 and last_progress_stage < 3:
                # Still stage 2, but update percentage
                self.update_progress(2, f"Zeek processing... {int(progress_pct)}%")
            
            # Check if files stopped growing (processing complete)
            if current_log_size == last_log_size:
                stable_count += 1
                if stable_count >= 3:  # Stable for 6 seconds
                    # Processing complete!
                    break
            else:
                stable_count = 0
                last_log_size = current_log_size
            
            await asyncio.sleep(2)
        
        # Check if we timed out
        if time.time() - start_time >= timeout:
            self.update_progress(0, "Processing timeout - check logs")
            return False
        
        # Stage 4: 100% - Complete
        self.update_progress(4, "Complete")
        
        return True


async def track_zeek_progress(progress_callback):
    """
    Track Zeek progress by monitoring log file growth
    
    Args:
        progress_callback: Function(stage, message) to update UI
    
    Returns:
        True if successful
    """
    tracker = RealZeekProgress(progress_callback)
    return await tracker.monitor_zeek()

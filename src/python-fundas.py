import time

start = time.monotonic()
time.sleep(1)
end = time.monotonic()
print(start//3600, end)
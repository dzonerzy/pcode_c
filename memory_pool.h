#pragma once

#include <vector>
#include <memory>
#include <stack>
#include <unordered_map>
#include <list>

constexpr size_t INITIAL_POOL_SIZE = 2048;
constexpr size_t EXPANSION_CHUNK_SIZE = 1024;

template <typename T, typename K>
class MemoryPool
{
    std::stack<T *> pool;
    std::vector<std::unique_ptr<T[]>> allocations;
    std::vector<size_t> allocationSizes; // Track sizes of allocations
    // std::unordered_map<K, T *> cache;         // Cache for frequently used instances keyed by K
    std::unordered_map<K, std::pair<T *, typename std::list<K>::iterator>> cache;
    std::unordered_map<T *, K> reverse_cache; // Reverse lookup to find key by object pointer

    std::list<K> usageOrder; // Tracks usage order, MRU at the front, LRU at the back
    size_t cacheLimit = 1024;

public:
    MemoryPool(size_t initial_size = INITIAL_POOL_SIZE)
    {
        cache.reserve(initial_size);
        reverse_cache.reserve(initial_size);
        allocations.reserve(initial_size / EXPANSION_CHUNK_SIZE + 1); // Estimate allocations
        expandPool(initial_size);
    }

    inline T *acquire()
    {
        if (pool.size() > 1)
        {
            __builtin_prefetch(pool.top()); // Prefetch the next object in the pool
        }
        if (pool.empty())
        {
            expandPool(EXPANSION_CHUNK_SIZE);
        }
        T *obj = pool.top();
        pool.pop();
        return obj;
    }

    T *acquireWithKey(const K &key)
    {
        auto it = cache.find(key);
        if (it != cache.end())
        {
            // Move the key to the front of the usageOrder (mark as MRU)
            usageOrder.splice(usageOrder.begin(), usageOrder, it->second.second);
            __builtin_prefetch(it->second.first); // Prefetch the cached object
            return it->second.first;              // Return the cached object
        }

        // Key not in cache; acquire a new object
        T *instance = acquire();

        // Add to usageOrder and cache
        usageOrder.push_front(key);                  // Add key to MRU position
        cache[key] = {instance, usageOrder.begin()}; // Store object and iterator in cache
        reverse_cache[instance] = key;               // Update reverse cache

        // Evict LRU if cache exceeds limit
        if (cache.size() > cacheLimit)
        {
            evictLRU(); // Evict least recently used object
        }

        return instance;
    }

    T **batchAcquire(size_t count, const std::vector<K> &keys = {})
    {
        T **array = new T *[count]; // Dynamically allocate memory for the array

        for (size_t i = 0; i < count; ++i)
        {
            if (i + 1 < count && !pool.empty())
            {
                __builtin_prefetch(pool.top()); // Prefetch the next object in the pool
            }

            if (!keys.empty() && i < keys.size())
            {
                // Use acquireWithKey if a key is provided
                array[i] = acquireWithKey(keys[i]);
            }
            else
            {
                // Regular acquire for elements without keys
                array[i] = acquire();
            }
        }

        return array; // Return the dynamically allocated array
    }

    T *acquireBlock(size_t count)
    {
        auto block = std::make_unique<T[]>(count);
        T *blockPtr = block.get();
        allocations.push_back(std::move(block)); // Keep the block in allocations to manage its lifetime
        return blockPtr;
    }

    inline void release(T *obj)
    {
        if (reverse_cache.erase(obj))
        {
            // If found and erased from reverse_cache, skip adding to pool
            return;
        }
        pool.push(obj); // Return the object to the pool
        releaseCount++;
        if (releaseCount % 100 == 0)
        {
            shrinkToFit();
        }

        // set the object to nullptr to avoid dangling pointers
        obj = nullptr;
    }

    void releaseWithKey(const K &key)
    {
        auto it = cache.find(key);
        if (it != cache.end())
        {
            // Remove the object from reverse cache
            reverse_cache.erase(it->second.first);

            // Remove from usageOrder
            usageOrder.erase(it->second.second);

            // Return the object to the pool
            pool.push(it->second.first);

            // Remove from cache
            cache.erase(it);

            // Shrink the pool if necessary
            if (releaseCount % 100 == 0)
            {
                shrinkToFit();
            }

            // even if we don't really release anything, we still need to update releaseCount
            releaseCount++;
        }
    }

    void batchRelease(T **array, size_t count)
    {
        for (size_t i = 0; i < count; ++i)
        {
            if (i + 1 < count)
            {
                __builtin_prefetch(array[i + 1]); // Prefetch the next object to release
            }
            auto reverse_it = reverse_cache.find(array[i]);
            if (reverse_it == reverse_cache.end())
            {
                pool.push(array[i]); // Only return to pool if not in cache
            }
        }
        delete[] array; // Safe deletion of dynamically allocated array
        // set the array to nullptr to avoid dangling pointers
        array = nullptr;
        releaseCount += count;
    }

    void shrinkToFit()
    {
        while (!allocations.empty() && pool.size() <= allocationSizes.back())
        {
            // Ensure no objects in the pool refer to this block
            T *block_start = allocations.back().get();
            T *block_end = block_start + allocationSizes.back();

            std::stack<T *> temp_pool;
            while (!pool.empty())
            {
                T *obj = pool.top();
                pool.pop();
                if (obj >= block_start && obj < block_end)
                {
                    // Object belongs to the block being deallocated; skip it
                    continue;
                }
                temp_pool.push(obj); // Keep the valid object
            }

            // Restore valid objects to the pool
            while (!temp_pool.empty())
            {
                pool.push(temp_pool.top());
                temp_pool.pop();
            }

            // Now it's safe to remove the block
            allocations.pop_back();
            allocationSizes.pop_back();
        }
    }

    void clear()
    {
        pool = std::stack<T *>();
        cache.clear();
        reverse_cache.clear();
        shrinkToFit(); // Free unused blocks
    }

    inline void evictLRU()
    {
        // Get the least recently used key (back of usageOrder list)
        const K &lruKey = usageOrder.back();

        // Get the object associated with the LRU key
        T *object = cache[lruKey].first;

        // Remove from cache and reverse_cache
        cache.erase(lruKey);
        reverse_cache.erase(object);

        // Remove the key from the usageOrder list
        usageOrder.pop_back();

        // Now the object is no longer in the cache and can be handled by release
    }

    size_t poolSize() const { return pool.size(); }
    size_t cacheSize() const { return cache.size(); }
    size_t reverseCacheSize() const { return reverse_cache.size(); }
    size_t allocationCount() const { return allocations.size(); }

private:
    size_t releaseCount = 0;
    size_t lastShrinkReleaseCount = 0;

    inline void expandPool(size_t count)
    {
        auto new_block = std::make_unique<T[]>(count);
        T *block_ptr = new_block.get();
        for (size_t i = 0; i < count; ++i)
        {
            if (i + 1 < count)
            {
                __builtin_prefetch(&block_ptr[i + 1]); // Prefetch the next object in the block
            }
            pool.push(block_ptr + i); // Push pointers sequentially
        }
        allocations.push_back(std::move(new_block));
        allocationSizes.push_back(count);
    }
};
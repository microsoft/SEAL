using System;
using System.Collections.Generic;
using System.Text;

namespace Microsoft.Research.SEAL
{
    public enum MMProfOpt : ulong
    {
        Default = 0,
        ForceGlobal = 1,
        ForceNew = 2,
        ForceThreadLocal = 4
    }

    /// <summary>
    /// The MemoryManager class can be used to create instances of MemoryPoolHandle 
    /// based on a given "profile". A profile is implemented by inheriting from the
    /// MMProf class (pure virtual) and encapsulates internal logic for deciding which
    /// memory pool to use.
    /// </summary>
    public static class MemoryManager
    {
        /// <summary>
        /// Returns a MemoryPoolHandle according to the currently set memory manager 
        /// profile and prof_opt. The following values for prof_opt have an effect 
        /// independent of the current profile:
        /// 
        /// 
        ///     MMProfOpt.ForceNew: return MemoryPoolHandle.New()
        ///     MMProfOpt.ForceGlobal: return MemoryPoolHandle.Global()
        ///     MMProfOpt.ForceThreadLocal: return MemoryPoolHandle.ThreadLocal()
        /// 
        /// Other values for prof_opt are forwarded to the current profile and, depending 
        /// on the profile, may or may not have an effect. The value mm_prof_opt::DEFAULT
        /// will always invoke a default behavior for the current profile.
        /// </summary>
        /// <param name="profOpt">A MMProfOpt parameter used to provide additional
        /// instructions to the memory manager profile for internal logic.</param>
        /// <param name="clearOnDestruction">Indicates whether the memory pool data 
        /// should be cleared when destroyed.This can be important when memory pools
        /// are used to store private data. This parameter is only used with MMProfOpt.ForceNew,
        /// and ignored in all other cases.</param>
        public static MemoryPoolHandle GetPool(MMProfOpt profOpt, bool clearOnDestruction = false)
        {
            NativeMethods.MemoryManager_GetPool((int)profOpt, clearOnDestruction, out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }

        /// <summary>
        /// Returns a MemoryPoolHandle according to the currently set memory manager profile.
        /// </summary>
        public static MemoryPoolHandle GetPool()
        {
            NativeMethods.MemoryManager_GetPool(out IntPtr handlePtr);
            MemoryPoolHandle handle = new MemoryPoolHandle(handlePtr);
            return handle;
        }
    }
}

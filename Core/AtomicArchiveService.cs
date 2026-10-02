using System;
using System.IO;
using System.IO.Compression;

namespace DomainMembershipCheckRepair
{
    internal static class AtomicArchiveService
    {
        internal static void CreateZipFromDirectoryAtomically(
            string sourceDirectory,
            string destinationPath)
        {
            if (String.IsNullOrWhiteSpace(sourceDirectory))
                throw new ArgumentException("A source directory is required.", "sourceDirectory");
            if (String.IsNullOrWhiteSpace(destinationPath))
                throw new ArgumentException("A destination archive path is required.", "destinationPath");

            string source = Path.GetFullPath(sourceDirectory);
            if (!Directory.Exists(source))
                throw new DirectoryNotFoundException("Archive source directory does not exist: " + source);

            string destination = Path.GetFullPath(destinationPath);
            string folder = Path.GetDirectoryName(destination);
            if (String.IsNullOrWhiteSpace(folder))
                throw new IOException("Archive destination has no parent directory.");

            if (!Directory.Exists(folder))
                Directory.CreateDirectory(folder);

            string temp =
                destination + ".tmp-" +
                Guid.NewGuid().ToString("N");

            try
            {
                ZipFile.CreateFromDirectory(
                    source,
                    temp,
                    CompressionLevel.Optimal,
                    false);

                VerifyArchive(temp);

                if (File.Exists(destination))
                    File.Replace(temp, destination, null);
                else
                    File.Move(temp, destination);

                VerifyArchive(destination);
            }
            finally
            {
                try
                {
                    if (File.Exists(temp))
                        File.Delete(temp);
                }
                catch
                {
                }
            }
        }

        internal static void VerifyArchive(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                throw new ArgumentException("An archive path is required.", "path");

            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
                throw new FileNotFoundException("Archive does not exist.", fullPath);

            FileInfo info = new FileInfo(fullPath);
            if (info.Length == 0)
                throw new InvalidDataException("Archive is empty.");

            using (ZipArchive archive = ZipFile.OpenRead(fullPath))
            {
                if (archive.Entries.Count == 0)
                    throw new InvalidDataException("Archive contains no entries.");

                foreach (ZipArchiveEntry entry in archive.Entries)
                {
                    if (String.IsNullOrWhiteSpace(entry.FullName))
                        throw new InvalidDataException("Archive contains an entry with an empty name.");
                }
            }
        }
    }
}

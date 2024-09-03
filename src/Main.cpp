#include <string>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <tink/streaming_aead.h>
#include <tink/util/ostream_output_stream.h>
#include <tink/keyset_handle.h>
#include <tink/streamingaead/streaming_aead_config.h>
#include <tink/streamingaead/streaming_aead_key_templates.h>

int main(int argc, char** argv) {

    if (argc != 2) {
        std::cout << "Provide a path to write to." << std::endl;
        return EXIT_FAILURE;
    }

    crypto::tink::StreamingAeadConfig::Register();
    const auto keyTemplate = crypto::tink::StreamingAeadKeyTemplates::Aes256GcmHkdf1MB();

    const auto keysetHandle{ crypto::tink::KeysetHandle::GenerateNew(keyTemplate, crypto::tink::KeyGenConfigGlobalRegistry()).value() };
    const auto primitive{ keysetHandle->GetPrimitive<crypto::tink::StreamingAead>(crypto::tink::ConfigGlobalRegistry()).value() };

    std::filesystem::path outputPath{ argv[1] };
    std::unique_ptr<std::ostream> baseStream{ std::make_unique<std::ofstream>(outputPath) };
    std::unique_ptr<crypto::tink::OutputStream> tinkStream{ std::make_unique<crypto::tink::util::OstreamOutputStream>(std::move(baseStream)) };

    const auto stream{ primitive->NewEncryptingStream(std::move(tinkStream), "").value() };

    char* destination{};
    const int destinationSize = stream->Next(reinterpret_cast<void**>(&destination)).value();

    constexpr char text{ '1' };
    memcpy(destination, &text, 1);

    stream->BackUp(destinationSize - 1);
    auto test{ stream->Close() }; // Will throw runtime assertion error on windows.
    if (!test.ok()) throw std::runtime_error("Error closing encrypting output stream");

    std::cout << "Completed" << std::endl;
}
